package collector

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/itom-mini/agent/internal/logger"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

type Sample struct {
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpuPercent"`
	MemoryPercent float64   `json:"memoryPercent"`
	DiskPercent   float64   `json:"diskPercent"`

	MemAvailableBytes uint64           `json:"memAvailableBytes,omitempty"`
	LoadAvg1m         *float64         `json:"loadAvg1m,omitempty"`
	ProcessCount      int              `json:"processCount,omitempty"`
	Network           []NetworkSample  `json:"network,omitempty"`
	Disks             []DiskSample     `json:"disks,omitempty"`
}

type NetworkSample struct {
	InterfaceName string `json:"interfaceName"`
	BytesSent     uint64 `json:"bytesSent"`
	BytesRecv     uint64 `json:"bytesRecv"`
	PacketsSent   uint64 `json:"packetsSent"`
	PacketsRecv   uint64 `json:"packetsRecv"`
}

type DiskSample struct {
	Mountpoint  string  `json:"mountpoint"`
	UsedPercent float64 `json:"usedPercent"`
	UsedBytes   uint64  `json:"usedBytes"`
	TotalBytes  uint64  `json:"totalBytes"`
}

type Collector struct {
	log      *logger.Logger
	diskPath string
}

func New(log *logger.Logger) *Collector {
	p := "/"
	if runtime.GOOS == "windows" {
		p = "C:\\"
	}
	return &Collector{log: log, diskPath: p}
}

// Collect blocks for ~500ms (CPU sampling window).
func (c *Collector) Collect(ctx context.Context) (Sample, error) {
	s := Sample{Timestamp: time.Now().UTC()}

	cpuPercents, err := cpu.PercentWithContext(ctx, 500*time.Millisecond, false)
	if err != nil {
		return s, err
	}
	if len(cpuPercents) > 0 {
		s.CPUPercent = cpuPercents[0]
	}

	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return s, err
	}
	s.MemoryPercent = vm.UsedPercent
	s.MemAvailableBytes = vm.Available

	du, err := disk.UsageWithContext(ctx, c.diskPath)
	if err != nil {
		return s, err
	}
	s.DiskPercent = du.UsedPercent

	if avg, err := load.AvgWithContext(ctx); err == nil && avg != nil {
		v := avg.Load1
		s.LoadAvg1m = &v
	}

	if pids, err := process.PidsWithContext(ctx); err == nil {
		s.ProcessCount = len(pids)
	}

	s.Network = collectNetwork(ctx)
	s.Disks = collectDisks(ctx)

	return s, nil
}

var skipIfacePrefixes = []string{
	"lo", "utun", "awdl", "llw", "bridge", "gif", "stf",
	"docker", "veth", "vmnet", "vethernet",
}

func ifaceDropped(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range skipIfacePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func collectNetwork(ctx context.Context) []NetworkSample {
	counters, err := net.IOCountersWithContext(ctx, true)
	if err != nil || len(counters) == 0 {
		return nil
	}
	out := make([]NetworkSample, 0, len(counters))
	for _, ic := range counters {
		if ifaceDropped(ic.Name) {
			continue
		}
		if ic.BytesSent+ic.BytesRecv == 0 {
			continue
		}
		out = append(out, NetworkSample{
			InterfaceName: ic.Name,
			BytesSent:     ic.BytesSent,
			BytesRecv:     ic.BytesRecv,
			PacketsSent:   ic.PacketsSent,
			PacketsRecv:   ic.PacketsRecv,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

var skipFstype = map[string]struct{}{
	"tmpfs": {}, "devfs": {}, "overlay": {}, "squashfs": {},
	"proc": {}, "sysfs": {}, "cgroup": {}, "cgroup2": {},
	"autofs": {}, "nsfs": {}, "tracefs": {},
}

func skipMountpoint(mp string) bool {
	if mp == "" {
		return true
	}
	prefixes := []string{"/snap/", "/var/lib/docker", "/proc", "/sys"}
	for _, p := range prefixes {
		if strings.HasPrefix(mp, p) {
			return true
		}
	}
	return false
}

func collectDisks(ctx context.Context) []DiskSample {
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil || len(parts) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]DiskSample, 0, len(parts))
	for _, p := range parts {
		mp := p.Mountpoint
		if skipMountpoint(mp) {
			continue
		}
		ft := strings.ToLower(strings.TrimSpace(p.Fstype))
		if _, skip := skipFstype[ft]; skip {
			continue
		}
		if _, dup := seen[mp]; dup {
			continue
		}
		usage, err := disk.UsageWithContext(ctx, mp)
		if err != nil || usage == nil || usage.Total == 0 {
			continue
		}
		seen[mp] = struct{}{}
		out = append(out, DiskSample{
			Mountpoint:  mp,
			UsedPercent: usage.UsedPercent,
			UsedBytes:   usage.Used,
			TotalBytes:  usage.Total,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
