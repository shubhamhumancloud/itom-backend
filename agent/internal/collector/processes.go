package collector

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	gopsproc "github.com/shirou/gopsutil/v4/process"
)

// TopProcesses samples all running processes and returns the union of top-N
// by CPU% and top-N by memory, aggregated by executable name (so Chrome's 12
// helper processes roll up to one row).
//
// CPU% returned by gopsutil is computed against an internal baseline; the
// first call returns 0. Caching the *Process objects between ticks would
// give us per-tick deltas, but at 60 s cadence the cumulative percent is
// fine for "which app is hot right now" — and far simpler.
type ProcessCollector struct {
	topByCPU int
	topByMem int

	// CPU sampler keeps a per-PID baseline so CPU% is the delta since the
	// previous tick — much more meaningful than gopsutil's lifetime average.
	mu      sync.Mutex
	prevCPU map[int32]processCPU
}

type processCPU struct {
	user   float64
	system float64
	at     time.Time
}

func NewProcessCollector(topByCPU, topByMem int) *ProcessCollector {
	if topByCPU <= 0 {
		topByCPU = 15
	}
	if topByMem <= 0 {
		topByMem = 15
	}
	return &ProcessCollector{
		topByCPU: topByCPU,
		topByMem: topByMem,
		prevCPU:  map[int32]processCPU{},
	}
}

// Collect returns one row per executable name, summed across PIDs.
// First call after start returns rows with cpuPercent=0 (no baseline yet).
func (pc *ProcessCollector) Collect(ctx context.Context) ([]ProcessSample, error) {
	pids, err := gopsproc.PidsWithContext(ctx)
	if err != nil {
		return nil, err
	}

	type agg struct {
		cpu   float64
		mem   uint64
		ioR   uint64
		ioW   uint64
		count int
	}
	byName := map[string]*agg{}

	now := time.Now()
	pc.mu.Lock()
	newCPU := map[int32]processCPU{}
	for _, pid := range pids {
		if ctx.Err() != nil {
			break
		}
		p, err := gopsproc.NewProcessWithContext(ctx, pid)
		if err != nil {
			continue
		}
		name, err := p.NameWithContext(ctx)
		if err != nil || name == "" {
			continue
		}
		name = strings.ToLower(name)

		// Per-PID CPU delta. Times() returns cumulative user+system seconds.
		cpuPct := 0.0
		if t, err := p.TimesWithContext(ctx); err == nil {
			cur := processCPU{user: t.User, system: t.System, at: now}
			if prev, ok := pc.prevCPU[pid]; ok {
				dt := cur.at.Sub(prev.at).Seconds()
				if dt > 0 {
					used := (cur.user + cur.system) - (prev.user + prev.system)
					if used > 0 {
						cpuPct = (used / dt) * 100.0
					}
				}
			}
			newCPU[pid] = cur
		}

		var memBytes uint64
		if mi, err := p.MemoryInfoWithContext(ctx); err == nil && mi != nil {
			memBytes = mi.RSS
		}

		var ioR, ioW uint64
		if io, err := p.IOCountersWithContext(ctx); err == nil && io != nil {
			ioR = io.ReadBytes
			ioW = io.WriteBytes
		}

		a := byName[name]
		if a == nil {
			a = &agg{}
			byName[name] = a
		}
		a.cpu += cpuPct
		a.mem += memBytes
		a.ioR += ioR
		a.ioW += ioW
		a.count++
	}
	pc.prevCPU = newCPU
	pc.mu.Unlock()

	if len(byName) == 0 {
		return nil, nil
	}

	type row struct {
		name string
		a    *agg
	}
	rows := make([]row, 0, len(byName))
	for n, a := range byName {
		rows = append(rows, row{n, a})
	}

	// Top-N by CPU.
	sort.Slice(rows, func(i, j int) bool { return rows[i].a.cpu > rows[j].a.cpu })
	keep := map[string]bool{}
	for i := 0; i < pc.topByCPU && i < len(rows); i++ {
		keep[rows[i].name] = true
	}
	// Top-N by memory.
	sort.Slice(rows, func(i, j int) bool { return rows[i].a.mem > rows[j].a.mem })
	for i := 0; i < pc.topByMem && i < len(rows); i++ {
		keep[rows[i].name] = true
	}

	out := make([]ProcessSample, 0, len(keep))
	for _, r := range rows {
		if !keep[r.name] {
			continue
		}
		// Cap CPU% at 100 * NumCPU equivalent — already in correct units.
		cpu := r.a.cpu
		if cpu < 0 {
			cpu = 0
		}
		out = append(out, ProcessSample{
			Name:         r.name,
			PIDCount:     r.a.count,
			CPUPercent:   roundTo(cpu, 2),
			MemoryBytes:  r.a.mem,
			IOReadBytes:  r.a.ioR,
			IOWriteBytes: r.a.ioW,
		})
	}
	return out, nil
}

func roundTo(v float64, digits int) float64 {
	mult := 1.0
	for i := 0; i < digits; i++ {
		mult *= 10
	}
	return float64(int64(v*mult+0.5)) / mult
}
