package crawl

import (
	"time"

	"github.com/itom-mini/collector/internal/discovery/fingerprint"
)

// fingerprintOpts produces tight timeouts so tests that hit the real
// Identify() path against unreachable addresses complete in well under
// a second per device.
func fingerprintOpts() fingerprint.Options {
	return fingerprint.Options{
		PerProbeTimeout: 50 * time.Millisecond,
		// Single port — keeps the scan fast even when nothing responds.
		PortsToScan: []int{443},
	}
}
