package paloalto

import (
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Factory matches device.Factory so the dispatcher registry can wire us
// in. The adapter (Login → ListContexts → Get* → observations + crawl
// hints) lives in firewall.GenericDriver — see fortigate/driver.go for
// the same one-liner pattern.
func Factory() device.Driver {
	return firewall.NewGenericDriver(
		device.VendorPaloAlto,
		func() firewall.Ingestor { return New() },
		nil, // chassis-serial extraction is a future polish
	)
}
