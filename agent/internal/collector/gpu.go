package collector

import (
	"context"
	"errors"
	"strings"
)

// ErrNoGPU is returned when no GPU could be discovered on the host. Callers
// should treat it as a non-error (skip emitting a frame, no alert) — it's the
// expected outcome on cloud VMs, locked-down corp boxes, etc.
var ErrNoGPU = errors.New("no gpu detected")

// CollectGPU returns inventory + live metrics for every GPU on the host.
//
// Inventory (Tier 1) is collected on every platform via OS-native APIs:
//   - macOS:   system_profiler SPDisplaysDataType
//   - Windows: WMI Win32_VideoController
//   - Linux:   /sys/class/drm + lspci
//
// Live metrics (Tier 2) — utilization / VRAM used / temperature / power —
// are overlaid by best-effort vendor tools when present:
//   - NVIDIA cards on any OS: nvidia-smi
//   - AMD ROCm cards on Linux/Windows: rocm-smi
//   - Apple Silicon on macOS: powermetrics
//   - Intel: deliberately skipped (requires root + intel_gpu_top; low value)
//
// Returns the union: every detected GPU plus whatever metrics we could
// gather. If no GPU is detected at all, returns ErrNoGPU.
func CollectGPU(ctx context.Context) ([]GPUSample, error) {
	samples := collectGPUInventory(ctx)
	if len(samples) == 0 {
		return nil, ErrNoGPU
	}
	overlayGPULiveMetrics(ctx, samples)
	return samples, nil
}

// splitCSV splits a CSV line on commas and trims each field. Shared by the
// nvidia-smi and rocm-smi overlays.
func splitCSV(line string) []string {
	parts := strings.Split(line, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// vendorFromName classifies a GPU by its model string. Used by every OS path
// when more specific signals (PCI ID, signed vendor) aren't available.
func vendorFromName(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "nvidia"), strings.Contains(n, "geforce"),
		strings.Contains(n, "quadro"), strings.Contains(n, "tesla"),
		strings.Contains(n, "rtx"), strings.Contains(n, "gtx"):
		return "nvidia"
	case strings.Contains(n, "amd"), strings.Contains(n, "radeon"),
		strings.Contains(n, "instinct"):
		return "amd"
	case strings.Contains(n, "intel"), strings.Contains(n, "iris"),
		strings.Contains(n, "uhd graphics"), strings.Contains(n, "arc "):
		return "intel"
	case strings.Contains(n, "apple m"), strings.HasPrefix(n, "apple ") &&
		!strings.Contains(n, "apple software"):
		return "apple"
	case strings.Contains(n, "qualcomm"), strings.Contains(n, "adreno"):
		return "qualcomm"
	case strings.Contains(n, "virtio"), strings.Contains(n, "vmware"),
		strings.Contains(n, "virtual"), strings.Contains(n, "qxl"):
		return "virtual"
	}
	return "unknown"
}
