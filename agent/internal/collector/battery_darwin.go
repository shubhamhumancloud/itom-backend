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
// so the reading matches what the macOS menu bar shows (Apple's IOKit raw
// percentage that distatus reads is uncalibrated and runs 2–4% lower) and
// fills in the lifetime cycle count via ioreg (distatus does not expose it).
//
// Each enrichment is independent — pmset failure does not block cycle count
// and vice versa. Distatus values are left in place on per-field failure.
func adjustBatteryForOS(ctx context.Context, r *BatteryReading) {
	if r == nil {
		return
	}
	if pct, charging, onAC, ok := parsePmsetBatt(ctx); ok {
		r.Percent = roundTo(pct, 2)
		r.Charging = charging
		r.OnAC = onAC
	}
	if cycles := readAppleSmartBatteryCycleCount(ctx); cycles > 0 {
		r.CycleCount = cycles
	}
}

// readAppleSmartBatteryCycleCount returns the lifetime CycleCount property
// from IOKit's AppleSmartBattery service (via ioreg, which doesn't need root).
// Returns 0 on any failure — caller leaves the field omitted.
//
// ioreg line of interest looks like:
//
//	"CycleCount" = 245
func readAppleSmartBatteryCycleCount(ctx context.Context) int {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "/usr/sbin/ioreg", "-rn", "AppleSmartBattery").Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "\"CycleCount\"") {
			continue
		}
		eq := strings.LastIndex(t, "=")
		if eq < 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(t[eq+1:]))
		if err != nil {
			return 0
		}
		return n
	}
	return 0
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
