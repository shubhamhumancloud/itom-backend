//go:build !darwin && !linux

package collector

import "context"

// adjustBatteryForOS is a no-op on Windows (and any other build target). The
// distatus library's readings already match what Windows shows in its native
// battery indicator, and cycle count via WMI's Win32_Battery is unreliable —
// most laptop firmware leaves the property unpopulated.
func adjustBatteryForOS(_ context.Context, _ *BatteryReading) {}
