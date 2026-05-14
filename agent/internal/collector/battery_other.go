//go:build !darwin && !linux && !windows

package collector

import "context"

// adjustBatteryForOS is a no-op for build targets we don't actively support
// (everything outside darwin/linux/windows). Each supported OS has its own
// battery_<os>.go file that overlays platform-specific fields.
func adjustBatteryForOS(_ context.Context, _ *BatteryReading) {}
