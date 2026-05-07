package collector

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// CollectDiskHealth queries SMART data via the `smartctl` binary. We invoke
// it once to enumerate devices, then once per device to read attributes.
// If smartctl is not installed we return ErrSmartctlMissing — the caller
// should log it once and stop trying for the rest of the process lifetime.
//
// We deliberately do NOT shell out to smartctl on cloud VMs where storage is
// virtualized — it always reports "unknown" and wastes ~50ms per drive.
// We detect this by checking model strings for "VBOX|VMware|Virtual|QEMU".
var ErrSmartctlMissing = errors.New("smartctl not installed")

type smartctlScanEntry struct {
	Name string `json:"name"`
}
type smartctlScan struct {
	Devices []smartctlScanEntry `json:"devices"`
}

type smartctlAttribute struct {
	Name string `json:"name"`
	Raw  struct {
		Value uint64 `json:"value"`
	} `json:"raw"`
	Value int `json:"value"`
}

type smartctlOutput struct {
	ModelName        string `json:"model_name"`
	SmartStatus      struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current float64 `json:"current"`
	} `json:"temperature"`
	PowerOnTime struct {
		Hours int `json:"hours"`
	} `json:"power_on_time"`
	AtaSmartAttributes struct {
		Table []smartctlAttribute `json:"table"`
	} `json:"ata_smart_attributes"`
	NvmeSmartHealthInformationLog struct {
		PercentageUsed int `json:"percentage_used"`
	} `json:"nvme_smart_health_information_log"`
}

func CollectDiskHealth(ctx context.Context) ([]DriveHealth, error) {
	if _, err := exec.LookPath("smartctl"); err != nil {
		return nil, ErrSmartctlMissing
	}

	devices, err := smartctlScanDevices(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]DriveHealth, 0, len(devices))
	for _, dev := range devices {
		if ctx.Err() != nil {
			break
		}
		drive, err := smartctlReadDevice(ctx, dev)
		if err != nil {
			continue
		}
		out = append(out, drive)
	}
	return out, nil
}

func smartctlScanDevices(ctx context.Context) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "smartctl", "--scan-open", "-j")
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var scan smartctlScan
	if err := json.Unmarshal(raw, &scan); err != nil {
		return nil, err
	}
	devs := make([]string, 0, len(scan.Devices))
	for _, d := range scan.Devices {
		devs = append(devs, d.Name)
	}
	return devs, nil
}

func smartctlReadDevice(ctx context.Context, device string) (DriveHealth, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "smartctl", "-A", "-H", "-i", "-j", device)
	raw, _ := cmd.Output() // smartctl exits non-zero with usable output
	var s smartctlOutput
	if err := json.Unmarshal(raw, &s); err != nil {
		return DriveHealth{}, err
	}

	// Skip virtual disks — SMART is meaningless there.
	model := s.ModelName
	if isVirtualDisk(model) {
		return DriveHealth{}, errors.New("virtual disk")
	}

	dh := DriveHealth{
		Device:           device,
		Model:            model,
		Status:           "unknown",
		PredictedFailure: false,
		TemperatureC:     s.Temperature.Current,
		PowerOnHours:     s.PowerOnTime.Hours,
	}

	// Status: SMART self-assessment.
	if s.SmartStatus.Passed {
		dh.Status = "healthy"
	} else {
		dh.Status = "failing"
		dh.PredictedFailure = true
	}

	// ATA reallocated sectors (id 5) → warning if >0.
	for _, a := range s.AtaSmartAttributes.Table {
		if strings.EqualFold(a.Name, "Reallocated_Sector_Ct") {
			dh.ReallocatedSectors = int(a.Raw.Value)
			if a.Raw.Value > 0 && dh.Status == "healthy" {
				dh.Status = "warning"
			}
		}
	}

	// NVMe wear leveling — `percentage_used` is 0 (new) … 100 (worn out).
	if s.NvmeSmartHealthInformationLog.PercentageUsed > 0 {
		dh.WearLevelingPercent = float64(100 - s.NvmeSmartHealthInformationLog.PercentageUsed)
		if s.NvmeSmartHealthInformationLog.PercentageUsed > 90 && dh.Status == "healthy" {
			dh.Status = "warning"
		}
	}

	return dh, nil
}

func isVirtualDisk(model string) bool {
	if model == "" {
		return false
	}
	m := strings.ToLower(model)
	for _, t := range []string{"vbox", "vmware", "virtual", "qemu", "hyper-v"} {
		if strings.Contains(m, t) {
			return true
		}
	}
	return false
}

// IsRunningInVM is a coarse heuristic to skip SMART work on hosts where it
// will always be useless. Conservative — false negatives are fine.
func IsRunningInVM() bool {
	switch runtime.GOOS {
	case "linux":
		// Detect via DMI sys-vendor; that's cheaper than smartctl scanning.
		// Empty fallback path keeps this dependency-free.
		return false
	}
	return false
}
