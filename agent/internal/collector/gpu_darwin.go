//go:build darwin

package collector

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// system_profiler SPDisplaysDataType -json shape (only fields we care about).
type spDisplaysGPU struct {
	Name             string         `json:"_name"`
	SPPCIModel       string         `json:"sppci_model"`
	SPDisplaysVendor string         `json:"spdisplays_vendor"`
	SPDisplaysVRAM   string         `json:"spdisplays_vram"`
	SPDisplaysVRAMS  string         `json:"spdisplays_vram_shared"`
	SPPCIBus         string         `json:"sppci_bus"`
	SPPCIDeviceType  string         `json:"sppci_device_type"`
	SPDisplaysMetal  string         `json:"spdisplays_metal_family"`
	SPDisplaysCores  string         `json:"spdisplays_gpu_core_count"`
	Displays         []spDisplaysOut `json:"spdisplays_ndrvs,omitempty"`
}

type spDisplaysOut struct {
	Name string `json:"_name"`
}

type spDisplaysOutput struct {
	GPUs []spDisplaysGPU `json:"SPDisplaysDataType"`
}

func collectGPUInventory(ctx context.Context) []GPUSample {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "system_profiler", "-json", "SPDisplaysDataType").Output()
	if err != nil {
		return nil
	}
	var parsed spDisplaysOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil
	}
	// Apple Silicon uses unified memory — the GPU can address all system RAM,
	// so we report the system RAM total as the "VRAM" for those GPUs. Look
	// it up once outside the per-GPU loop.
	unifiedMem := unifiedMemoryBytes(ctx)

	samples := make([]GPUSample, 0, len(parsed.GPUs))
	for i, g := range parsed.GPUs {
		name := firstNonEmpty(g.SPPCIModel, g.Name)
		if name == "" {
			continue
		}
		vendor := vendorFromName(name)
		// Apple Silicon and Intel Mac integrated GPUs report sppci_bus="spdisplays_builtin".
		// Discrete cards report "spdisplays_pcie_device" or similar.
		slot := "unknown"
		switch {
		case strings.Contains(g.SPPCIBus, "builtin"):
			slot = "integrated"
		case strings.Contains(g.SPPCIBus, "pcie"), strings.Contains(g.SPPCIBus, "pci"):
			slot = "discrete"
		case strings.Contains(g.SPPCIBus, "external"):
			slot = "egpu"
		}
		mem := parseMacVRAM(firstNonEmpty(g.SPDisplaysVRAM, g.SPDisplaysVRAMS))
		if mem == 0 && vendor == "apple" {
			mem = unifiedMem // shared with system RAM on Apple Silicon
		}
		samples = append(samples, GPUSample{
			Index:            i,
			Name:             name,
			Vendor:           vendor,
			SlotType:         slot,
			MemoryTotalBytes: mem,
		})
	}
	return samples
}

// unifiedMemoryBytes returns the system RAM size on macOS via `sysctl hw.memsize`.
// Used as the "VRAM total" for Apple Silicon GPUs (unified memory). Returns 0
// on failure; caller treats that as "unknown."
func unifiedMemoryBytes(ctx context.Context) uint64 {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "/usr/sbin/sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// parseMacVRAM turns strings like "18 GB" / "1536 MB" / "Dynamic, up to..." into bytes.
// Returns 0 on values we can't parse — better than guessing.
func parseMacVRAM(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Pull the first number out of strings like "18 GB" or "Dynamic, up to 1536 MB".
	var numEnd int
	var numStart int
	for i, ch := range s {
		if ch >= '0' && ch <= '9' || ch == '.' {
			if numEnd == numStart && numStart == 0 && i > 0 {
				numStart = i
			}
			numEnd = i + 1
		} else if numEnd > numStart {
			break
		}
	}
	if numEnd == 0 {
		return 0
	}
	n, err := strconv.ParseFloat(s[numStart:numEnd], 64)
	if err != nil || n <= 0 {
		return 0
	}
	upper := strings.ToUpper(s)
	switch {
	case strings.Contains(upper, "GB"):
		return uint64(n * 1024 * 1024 * 1024)
	case strings.Contains(upper, "MB"):
		return uint64(n * 1024 * 1024)
	case strings.Contains(upper, "KB"):
		return uint64(n * 1024)
	}
	// No unit → assume MB (most common in system_profiler output)
	return uint64(n * 1024 * 1024)
}

func firstNonEmpty(opts ...string) string {
	for _, s := range opts {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// overlayPlatformSpecific runs Apple Silicon-specific live metrics via
// `powermetrics --samplers gpu_power`. Only fires if at least one sample
// is an Apple GPU. Requires root, which the agent has when installed as
// a launchd service.
//
// We accept a ~1s sample window for one tick per minute — the overhead
// is negligible. Failures are silent.
func overlayPlatformSpecific(ctx context.Context, samples []GPUSample) {
	if !hasAppleGPU(samples) {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "/usr/bin/powermetrics",
		"--samplers", "gpu_power",
		"-n", "1",
		"-i", "1000",
	).Output()
	if err != nil {
		return
	}
	util, power, ok := parsePowermetricsGPU(string(out))
	if !ok {
		return
	}
	// Apple Silicon has a single GPU — apply the metrics to it.
	for i := range samples {
		if samples[i].Vendor == "apple" {
			samples[i].UtilizationPercent = util
			samples[i].PowerWatts = power
			break
		}
	}
}

func hasAppleGPU(samples []GPUSample) bool {
	for _, s := range samples {
		if s.Vendor == "apple" {
			return true
		}
	}
	return false
}

// parsePowermetricsGPU extracts GPU utilization (%) and power (W) from the
// text-format output of `powermetrics --samplers gpu_power`. Looks for the
// "GPU HW active residency:" and "GPU Power:" lines and returns the numeric
// values. Returns ok=false if neither line was found.
func parsePowermetricsGPU(out string) (utilPct, powerWatts float64, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trim, "GPU HW active residency:"):
			rest := strings.TrimPrefix(trim, "GPU HW active residency:")
			if v, err := parseFirstFloat(rest); err == nil {
				utilPct = v
				ok = true
			}
		case strings.HasPrefix(trim, "GPU Power:"):
			rest := strings.TrimPrefix(trim, "GPU Power:")
			if v, err := parseFirstFloat(rest); err == nil {
				// powermetrics on Apple Silicon reports in milliwatts.
				// Convert to W so the dashboard's "W" label is correct.
				if strings.Contains(rest, "mW") {
					powerWatts = v / 1000.0
				} else {
					powerWatts = v
				}
				ok = true
			}
		}
	}
	return utilPct, powerWatts, ok
}

// parseFirstFloat pulls the first decimal number out of a string. Useful
// when output mixes the number with units and parenthesised detail.
func parseFirstFloat(s string) (float64, error) {
	var start, end int = -1, -1
	for i, ch := range s {
		if (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' {
			if start == -1 {
				start = i
			}
			end = i + 1
		} else if start != -1 {
			break
		}
	}
	if start == -1 {
		return 0, strconv.ErrSyntax
	}
	return strconv.ParseFloat(s[start:end], 64)
}
