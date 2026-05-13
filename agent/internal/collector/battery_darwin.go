//go:build darwin

package collector

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// adjustBatteryForOS overlays the percent + charging state from `pmset -g batt`
// so the reading matches what the macOS menu bar shows. Apple's IOKit raw
// percentage (used by distatus) is uncalibrated and runs 2–4% lower than the
// calibrated value the menu bar / Activity Monitor display.
//
// If pmset parsing fails for any reason we leave the distatus values in place.
func adjustBatteryForOS(ctx context.Context, r *BatteryReading) {
	if r == nil {
		return
	}
	pct, charging, onAC, ok := parsePmsetBatt(ctx)
	if !ok {
		return
	}
	r.Percent = roundTo(pct, 2)
	r.Charging = charging
	r.OnAC = onAC
}

// pmset output line we care about looks like:
//
//	 -InternalBattery-0 (id=12345678)	83%; discharging; 5:23 remaining present: true
//
// or, when fully charged:
//
//	 -InternalBattery-0 (id=12345678)	100%; charged; 0:00 remaining present: true
var pmsetPctRe = regexp.MustCompile(`(\d{1,3})%`)

func parsePmsetBatt(ctx context.Context) (percent float64, charging, onAC, ok bool) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(cctx, "/usr/bin/pmset", "-g", "batt").Output()
	if err != nil {
		return 0, false, false, false
	}
	text := string(out)

	onAC = strings.Contains(text, "'AC Power'")

	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "-") {
			continue
		}
		m := pmsetPctRe.FindStringSubmatch(t)
		if len(m) < 2 {
			continue
		}
		p, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			continue
		}
		// "discharging" must be checked before "charging" because the former
		// contains the latter as a substring.
		switch {
		case strings.Contains(t, "discharging"):
			charging = false
		case strings.Contains(t, "charging"):
			charging = true
		case strings.Contains(t, "charged"):
			charging = false
			onAC = true
		}
		return p, charging, onAC, true
	}
	return 0, false, false, false
}
