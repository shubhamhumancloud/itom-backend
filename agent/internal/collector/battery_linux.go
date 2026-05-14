//go:build linux

package collector

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// adjustBatteryForOS fills in fields the distatus library doesn't expose on
// Linux. Currently: lifetime cycle count from sysfs. Percent / charging /
// AC state from distatus already match what GNOME / KDE indicators show, so
// no overlay is needed there.
func adjustBatteryForOS(_ context.Context, r *BatteryReading) {
	if r == nil {
		return
	}
	if cycles := readSysfsBatteryCycleCount(); cycles > 0 {
		r.CycleCount = cycles
	}
}

// readSysfsBatteryCycleCount reads cycle_count from each BAT* entry under
// /sys/class/power_supply and returns the largest value (multi-battery
// laptops are rare but exist; take the worst-case wear indicator). Returns
// 0 when there is no battery directory, no cycle_count file, or the value
// is unparseable — sysfs sometimes reports "0" for batteries whose embedded
// controller doesn't surface a cycle counter.
func readSysfsBatteryCycleCount() int {
	entries, err := filepath.Glob("/sys/class/power_supply/BAT*/cycle_count")
	if err != nil || len(entries) == 0 {
		return 0
	}
	var max int
	for _, p := range entries {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	return max
}
