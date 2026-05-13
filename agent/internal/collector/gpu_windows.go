//go:build windows

package collector

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

// Win32_VideoController fields we care about (PowerShell ConvertTo-Json output).
type win32VideoCtrl struct {
	Name              string `json:"Name"`
	AdapterRAM        uint64 `json:"AdapterRAM"`
	DriverVersion     string `json:"DriverVersion"`
	VideoProcessor    string `json:"VideoProcessor"`
	AdapterCompatibility string `json:"AdapterCompatibility"`
	PNPDeviceID       string `json:"PNPDeviceID"`
}

func collectGPUInventory(ctx context.Context) []GPUSample {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// PowerShell returns single object for one row, array for many.
	const ps = `Get-CimInstance Win32_VideoController |
		Select-Object Name, AdapterRAM, DriverVersion, VideoProcessor, AdapterCompatibility, PNPDeviceID |
		ConvertTo-Json -Compress`
	out, err := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	var entries []win32VideoCtrl
	if err := json.Unmarshal(out, &entries); err != nil {
		var single win32VideoCtrl
		if err := json.Unmarshal(out, &single); err != nil {
			return nil
		}
		entries = []win32VideoCtrl{single}
	}

	samples := make([]GPUSample, 0, len(entries))
	for i, e := range entries {
		if e.Name == "" {
			continue
		}
		vendor := vendorFromName(e.Name)
		if vendor == "unknown" && e.AdapterCompatibility != "" {
			vendor = vendorFromName(e.AdapterCompatibility)
		}
		// Windows: discrete GPUs typically have higher AdapterRAM AND a PNPDeviceID
		// starting with "PCI\VEN_". Integrated GPUs also report this, so we use
		// the name as the better discriminator (Intel UHD/Iris → integrated).
		slot := "discrete"
		if vendor == "intel" && (strings.Contains(strings.ToLower(e.Name), "uhd") ||
			strings.Contains(strings.ToLower(e.Name), "iris") ||
			strings.Contains(strings.ToLower(e.Name), "hd graphics")) {
			slot = "integrated"
		}
		if strings.Contains(e.PNPDeviceID, "ROOT\\BasicDisplay") {
			slot = "virtual" // Microsoft Basic Display Adapter on VMs
		}
		samples = append(samples, GPUSample{
			Index:            i,
			Name:             e.Name,
			Vendor:           vendor,
			DriverVersion:    e.DriverVersion,
			SlotType:         slot,
			MemoryTotalBytes: e.AdapterRAM,
		})
	}
	return samples
}

// overlayPlatformSpecific is a no-op on Windows. Cross-vendor live metrics
// (NVIDIA / AMD) are handled by the shared overlay code.
func overlayPlatformSpecific(_ context.Context, _ []GPUSample) {}
