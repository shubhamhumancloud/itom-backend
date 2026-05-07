package collector

import (
	"context"
	"strings"

	"github.com/shirou/gopsutil/v4/sensors"
)

// CollectSensors returns CPU temperatures (and fan RPMs where the OS exposes
// them). On Linux it reads /sys/class/hwmon. On Windows it queries WMI. On
// macOS it reads SMC. Whatever gopsutil exposes, we forward verbatim.
//
// On hosts where no sensors are accessible (cloud VMs, locked-down corp
// machines), this returns an empty slice — caller should not emit a frame.
func CollectSensors(ctx context.Context) ([]SensorReading, error) {
	temps, err := sensors.TemperaturesWithContext(ctx)
	if err != nil {
		// gopsutil returns Warnings as errors when *some* sensors fail;
		// don't drop usable data because a few were unreadable.
		var warns *sensors.Warnings
		if !errorsAsWarnings(err, &warns) {
			return nil, err
		}
	}

	out := make([]SensorReading, 0, len(temps))
	for _, t := range temps {
		if t.Temperature <= 0 {
			continue
		}
		key := strings.ToLower(t.SensorKey)
		kind := "temperature_c"
		if strings.Contains(key, "fan") {
			kind = "fan_rpm"
		}
		out = append(out, SensorReading{
			Name:  t.SensorKey,
			Kind:  kind,
			Value: roundTo(t.Temperature, 1),
		})
	}
	return out, nil
}

// sensors.Warnings implements `error`. We want to keep partial data when it does.
func errorsAsWarnings(err error, target **sensors.Warnings) bool {
	if err == nil {
		return false
	}
	if w, ok := err.(*sensors.Warnings); ok {
		*target = w
		return true
	}
	return false
}
