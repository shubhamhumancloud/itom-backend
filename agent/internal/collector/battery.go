package collector

import (
	"context"
	"errors"

	"github.com/distatus/battery"
)

// CollectBattery returns a single Battery snapshot if a battery is present,
// or (nil, ErrNoBattery) on machines without one. Cross-platform: Windows
// (Win32_Battery), macOS (IOKit), Linux (/sys/class/power_supply).
//
// We aggregate across multi-battery laptops by averaging % and summing
// capacities. Most users have one battery; the aggregation is a safe default.
var ErrNoBattery = errors.New("no battery present")

func CollectBattery(ctx context.Context) (*BatteryReading, error) {
	bats, err := battery.GetAll()
	if err != nil || len(bats) == 0 {
		// distatus returns ErrFatal/ErrPartial on partial reads; treat as no battery.
		return nil, ErrNoBattery
	}

	var (
		curSum, fullSum, designSum float64
		charging, ac               bool
		cycles                     int
	)
	for _, b := range bats {
		if b == nil {
			continue
		}
		curSum += b.Current
		fullSum += b.Full
		designSum += b.Design
		switch b.State.Raw {
		case battery.Charging:
			charging = true
			ac = true
		case battery.Full:
			ac = true
		case battery.Discharging, battery.Empty:
			// not on AC
		default:
			// Unknown — leave defaults.
		}
		// distatus does not expose cycle count; leave at 0 (omitted in JSON).
		_ = cycles
	}

	if fullSum <= 0 {
		return nil, ErrNoBattery
	}

	percent := (curSum / fullSum) * 100.0
	if percent > 100 {
		percent = 100
	}
	if percent < 0 {
		percent = 0
	}

	healthPct := 0.0
	if designSum > 0 {
		healthPct = (fullSum / designSum) * 100.0
		if healthPct > 100 {
			healthPct = 100
		}
	}

	reading := &BatteryReading{
		Percent:           roundTo(percent, 2),
		Charging:          charging,
		OnAC:              ac,
		DesignCapacityMwh: int(designSum),
		FullCapacityMwh:   int(fullSum),
		HealthPercent:     roundTo(healthPct, 2),
	}
	// macOS: overlay percent + charging state from pmset so it matches the
	// menu bar. No-op on Linux/Windows.
	adjustBatteryForOS(ctx, reading)
	return reading, nil
}
