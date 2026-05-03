package info

import (
	"context"
	"net"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

type Device struct {
	Hostname         string   `json:"hostname"`
	OS               string   `json:"os"`
	Arch             string   `json:"arch"`
	Platform         string   `json:"platform"`
	PlatformVersion  string   `json:"platformVersion"`
	KernelVersion    string   `json:"kernelVersion"`
	EthernetIPs      []string `json:"ethernetIPs"`
	WifiIPs          []string `json:"wifiIPs"`
	MACAddresses     []string `json:"macAddresses"`
	CPUModel         string   `json:"cpuModel"`
	CPUCores         int      `json:"cpuCores"`
	TotalMemoryBytes uint64   `json:"totalMemoryBytes"`
	TotalDiskBytes   uint64   `json:"totalDiskBytes"`
}

func Collect(ctx context.Context) Device {
	d := Device{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	if hi, err := host.InfoWithContext(ctx); err == nil {
		d.Hostname = hi.Hostname
		d.Platform = hi.Platform
		d.PlatformVersion = hi.PlatformVersion
		d.KernelVersion = hi.KernelVersion
	}

	if infos, err := cpu.InfoWithContext(ctx); err == nil && len(infos) > 0 {
		d.CPUModel = infos[0].ModelName
	}
	if count, err := cpu.CountsWithContext(ctx, true); err == nil {
		d.CPUCores = count
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		d.TotalMemoryBytes = vm.Total
	}

	diskPath := "/"
	if runtime.GOOS == "windows" {
		diskPath = "C:\\"
	}
	if du, err := disk.UsageWithContext(ctx, diskPath); err == nil {
		d.TotalDiskBytes = du.Total
	}

	d.EthernetIPs, d.WifiIPs, d.MACAddresses = collectNetworkInfo()
	return d
}

func collectNetworkInfo() (ethernetIPs, wifiIPs, macAddresses []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	seenMACs := make(map[string]bool)

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue // skip virtual/tunnel interfaces with no MAC
		}

		// Collect unique MAC addresses
		if !seenMACs[mac] {
			seenMACs[mac] = true
			macAddresses = append(macAddresses, mac)
		}

		// Collect only IPv4 addresses
		addrs, _ := iface.Addrs()
		var ipv4s []string
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				ipv4s = append(ipv4s, ip.String())
			}
		}

		if len(ipv4s) == 0 {
			continue
		}

		switch guessInterfaceType(iface.Name) {
		case "wifi":
			wifiIPs = append(wifiIPs, ipv4s...)
		case "ethernet":
			ethernetIPs = append(ethernetIPs, ipv4s...)
		}
	}
	return
}

// guessInterfaceType classifies an interface as ethernet, wifi, or other
// based on naming conventions across Windows, Linux, and macOS.
func guessInterfaceType(name string) string {
	lower := strings.ToLower(name)

	wifiPrefixes := []string{"wi-fi", "wifi", "wireless", "wlan", "wlp", "airport"}
	for _, p := range wifiPrefixes {
		if strings.Contains(lower, p) {
			return "wifi"
		}
	}

	ethernetPrefixes := []string{"ethernet", "eth", "ens", "enp", "local area"}
	for _, p := range ethernetPrefixes {
		if strings.Contains(lower, p) {
			return "ethernet"
		}
	}

	// macOS: en0 is WiFi on most MacBooks, en1+ is Thunderbolt/USB Ethernet
	if lower == "en0" {
		return "wifi"
	}
	if strings.HasPrefix(lower, "en") {
		return "ethernet"
	}

	return "other"
}
