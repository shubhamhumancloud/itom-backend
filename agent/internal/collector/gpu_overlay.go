package collector

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// overlayGPULiveMetrics fills in utilization, VRAM used, temperature, and
// power draw on the inventory samples. Strategy:
//
//   - For NVIDIA cards: nvidia-smi (universal, NVIDIA-supplied).
//   - For AMD cards: rocm-smi if installed (rare outside ML rigs).
//   - For Apple Silicon: powermetrics (macOS-only, agent runs as root).
//   - For Intel / unknown: leave live fields at zero. Inventory still shows up.
//
// All overlays are best-effort. A failed/missing tool never fails the
// collection — the row just keeps the inventory fields and zero metrics.
func overlayGPULiveMetrics(ctx context.Context, samples []GPUSample) {
	if hasNvidia := anyVendor(samples, "nvidia"); hasNvidia {
		overlayNvidiaSMI(ctx, samples)
	}
	if hasAMD := anyVendor(samples, "amd"); hasAMD {
		overlayROCmSMI(ctx, samples)
	}
	overlayPlatformSpecific(ctx, samples)
}

func anyVendor(samples []GPUSample, vendor string) bool {
	for _, s := range samples {
		if s.Vendor == vendor {
			return true
		}
	}
	return false
}

// ----- NVIDIA via nvidia-smi -----------------------------------------------

const nvidiaSMIQuery = "index,name,driver_version,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw"

func overlayNvidiaSMI(ctx context.Context, samples []GPUSample) {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "nvidia-smi",
		"--query-gpu="+nvidiaSMIQuery,
		"--format=csv,noheader,nounits",
	).Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := splitCSV(line)
		if len(fields) < 8 {
			continue
		}
		name := strings.TrimSpace(fields[1])
		idx, target := findNvidiaTarget(samples, name)
		if target == nil {
			continue
		}
		_ = idx
		// nvidia-smi gives us driver version and authoritative live metrics.
		target.DriverVersion = strings.TrimSpace(fields[2])
		if v, err := strconv.ParseFloat(strings.TrimSpace(fields[3]), 64); err == nil {
			target.UtilizationPercent = v
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(fields[4]), 64); err == nil {
			target.MemoryUsedBytes = uint64(v * 1024 * 1024)
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(fields[5]), 64); err == nil {
			// nvidia-smi memory.total is authoritative for VRAM size.
			target.MemoryTotalBytes = uint64(v * 1024 * 1024)
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(fields[6]), 64); err == nil {
			target.TemperatureC = v
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(fields[7]), 64); err == nil {
			target.PowerWatts = v
		}
	}
}

// findNvidiaTarget matches an nvidia-smi row back to its inventory sample by
// name. Returns nil if no match (sample shape changed between calls).
func findNvidiaTarget(samples []GPUSample, name string) (int, *GPUSample) {
	for i := range samples {
		if samples[i].Vendor != "nvidia" {
			continue
		}
		if strings.EqualFold(samples[i].Name, name) ||
			strings.Contains(strings.ToLower(samples[i].Name), strings.ToLower(name)) ||
			strings.Contains(strings.ToLower(name), strings.ToLower(samples[i].Name)) {
			return i, &samples[i]
		}
	}
	return -1, nil
}

// ----- AMD via rocm-smi ----------------------------------------------------

// rocm-smi --showuse --showmeminfo vram --showtemp --showpower --json on a
// machine with one Instinct/Radeon Pro returns roughly:
//
//	{
//	  "card0": {
//	    "GPU use (%)": "42",
//	    "VRAM Total Memory (B)": "17163091968",
//	    "VRAM Total Used Memory (B)": "1234567890",
//	    "Temperature (Sensor edge) (C)": "58.0",
//	    "Average Graphics Package Power (W)": "150.0"
//	  }
//	}
//
// Naming differs slightly across rocm-smi versions; we tolerate variations.
func overlayROCmSMI(ctx context.Context, samples []GPUSample) {
	if _, err := exec.LookPath("rocm-smi"); err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "rocm-smi",
		"--showuse", "--showmeminfo", "vram", "--showtemp", "--showpower",
		"--csv",
	).Output()
	if err != nil || len(out) == 0 {
		return
	}
	// CSV header line + one row per card. Parse positionally.
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return
	}
	header := splitCSV(lines[0])
	idx := func(key string) int {
		k := strings.ToLower(key)
		for i, h := range header {
			if strings.Contains(strings.ToLower(h), k) {
				return i
			}
		}
		return -1
	}
	iUse := idx("gpu use")
	iVramTotal := idx("vram total memory")
	iVramUsed := idx("vram total used memory")
	iTemp := idx("temperature")
	iPower := idx("power")

	amdIdx := 0
	for _, line := range lines[1:] {
		fields := splitCSV(line)
		target := findAMDTarget(samples, amdIdx)
		amdIdx++
		if target == nil {
			continue
		}
		if iUse >= 0 && iUse < len(fields) {
			if v, err := strconv.ParseFloat(strings.TrimSpace(fields[iUse]), 64); err == nil {
				target.UtilizationPercent = v
			}
		}
		if iVramTotal >= 0 && iVramTotal < len(fields) {
			if v, err := strconv.ParseUint(strings.TrimSpace(fields[iVramTotal]), 10, 64); err == nil {
				target.MemoryTotalBytes = v
			}
		}
		if iVramUsed >= 0 && iVramUsed < len(fields) {
			if v, err := strconv.ParseUint(strings.TrimSpace(fields[iVramUsed]), 10, 64); err == nil {
				target.MemoryUsedBytes = v
			}
		}
		if iTemp >= 0 && iTemp < len(fields) {
			if v, err := strconv.ParseFloat(strings.TrimSpace(fields[iTemp]), 64); err == nil {
				target.TemperatureC = v
			}
		}
		if iPower >= 0 && iPower < len(fields) {
			if v, err := strconv.ParseFloat(strings.TrimSpace(fields[iPower]), 64); err == nil {
				target.PowerWatts = v
			}
		}
	}
}

// findAMDTarget pairs the Nth rocm-smi card row to the Nth AMD inventory sample.
// rocm-smi enumerates AMD cards in PCI order; inventory paths do the same.
func findAMDTarget(samples []GPUSample, nth int) *GPUSample {
	count := 0
	for i := range samples {
		if samples[i].Vendor != "amd" {
			continue
		}
		if count == nth {
			return &samples[i]
		}
		count++
	}
	return nil
}
