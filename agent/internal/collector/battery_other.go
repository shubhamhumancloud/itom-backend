//go:build !darwin

package collector

import "context"

// adjustBatteryForOS is a no-op on Linux and Windows. The distatus library's
// readings already match what those operating systems show in their native
// battery indicators — no calibration overlay needed.
func adjustBatteryForOS(_ context.Context, _ *BatteryReading) {}
