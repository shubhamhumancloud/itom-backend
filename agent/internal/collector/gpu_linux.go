//go:build linux

package collector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PCI vendor IDs — small embedded map keeps us from depending on a system
// pci.ids file (which isn't always present, e.g. minimal containers).
var pciVendorByID = map[string]string{
	"0x10de": "nvidia",
	"0x1002": "amd",
	"0x1022": "amd",
	"0x8086": "intel",
	"0x1ae0": "google", // GVT-g virtual
	"0x1af4": "virtual", // virtio
	"0x15ad": "virtual", // VMware
	"0x1234": "virtual", // QEMU stdvga
}

func collectGPUInventory(ctx context.Context) []GPUSample {
	// /sys/class/drm/card*/device/vendor + device gives us PCI IDs for every GPU.
	// We pair that with the corresponding name from lspci when available.
	cards, err := filepath.Glob("/sys/class/drm/card[0-9]*")
	if err != nil || len(cards) == 0 {
		return nil
	}
	sort.Strings(cards)

	names := lspciVGANames(ctx) // best-effort, may be empty

	samples := make([]GPUSample, 0, len(cards))
	seenPciAddr := make(map[string]struct{}, len(cards))
	for i, card := range cards {
		// Skip card1, card2... that are render nodes for the same GPU
		// (their device symlink resolves to the same PCI address).
		pciAddr := pciAddrOfDRMCard(card)
		if pciAddr == "" {
			continue
		}
		if _, dup := seenPciAddr[pciAddr]; dup {
			continue
		}
		seenPciAddr[pciAddr] = struct{}{}

		vendorID := strings.TrimSpace(readSysfs(card + "/device/vendor"))
		vendor := pciVendorByID[strings.ToLower(vendorID)]
		if vendor == "" {
			vendor = "unknown"
		}

		name := names[pciAddr]
		if name == "" {
			// Last-ditch fallback: PCI ID strings.
			deviceID := strings.TrimSpace(readSysfs(card + "/device/device"))
			name = vendor + " " + deviceID
		}

		// On Linux, integrated GPUs typically share the system DRAM and
		// don't report a dedicated VRAM size via sysfs. We leave
		// MemoryTotalBytes=0 in that case — accurate sizes come from
		// vendor tools (nvidia-smi, rocm-smi) at the overlay step.
		slot := "discrete"
		if vendor == "intel" {
			slot = "integrated"
		}
		if vendor == "virtual" {
			slot = "virtual"
		}

		samples = append(samples, GPUSample{
			Index:    i,
			Name:     name,
			Vendor:   vendor,
			SlotType: slot,
		})
	}
	return samples
}

// readSysfs reads a tiny sysfs file and returns its contents as a string.
// Errors return "" — sysfs access is rarely interesting to log.
func readSysfs(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// pciAddrOfDRMCard returns the BDF (bus:device.function) of a /sys/class/drm
// card by resolving its `device` symlink.
func pciAddrOfDRMCard(cardPath string) string {
	target, err := os.Readlink(cardPath + "/device")
	if err != nil {
		return ""
	}
	return filepath.Base(target) // e.g. "0000:01:00.0"
}

// lspciVGANames runs `lspci -mm` (machine-readable) and extracts a map of
// PCI address → display device name. Best-effort: empty map on failure.
func lspciVGANames(ctx context.Context) map[string]string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "lspci", "-mm").Output()
	if err != nil {
		return map[string]string{}
	}
	// Format: "01:00.0 "VGA compatible controller" "NVIDIA Corporation" "GA102 [GeForce RTX 3080]" ...
	names := make(map[string]string, 4)
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "VGA") && !strings.Contains(line, "3D") &&
			!strings.Contains(line, "Display") {
			continue
		}
		fields := splitLSPCI(line)
		if len(fields) < 4 {
			continue
		}
		// fields[0] = BDF, fields[2] = vendor, fields[3] = device
		bdf := strings.TrimSpace(fields[0])
		// Normalise to match /sys/class/drm format which includes domain prefix.
		if !strings.Contains(bdf, ":") {
			continue
		}
		if !strings.HasPrefix(bdf, "0000:") {
			bdf = "0000:" + bdf
		}
		names[bdf] = strings.Trim(fields[2], "\"") + " " + strings.Trim(fields[3], "\"")
	}
	return names
}

// overlayPlatformSpecific is a no-op on Linux. NVIDIA cards are filled in by
// the shared nvidia-smi overlay; AMD by rocm-smi. Intel integrated graphics
// are intentionally left without live metrics (needs root + intel_gpu_top).
func overlayPlatformSpecific(_ context.Context, _ []GPUSample) {}

// splitLSPCI splits a `lspci -mm` line on spaces, keeping quoted segments intact.
func splitLSPCI(line string) []string {
	var fields []string
	var cur strings.Builder
	inQuote := false
	for _, ch := range line {
		switch {
		case ch == '"':
			inQuote = !inQuote
			cur.WriteRune(ch)
		case ch == ' ' && !inQuote:
			if cur.Len() > 0 {
				fields = append(fields, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(ch)
		}
	}
	if cur.Len() > 0 {
		fields = append(fields, cur.String())
	}
	return fields
}
