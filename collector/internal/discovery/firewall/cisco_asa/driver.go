package cisco_asa

import (
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Factory wires the ASA Ingestor into the dispatcher's driver registry
// via the shared firewall.GenericDriver adapter.
func Factory() device.Driver {
	return firewall.NewGenericDriver(
		device.VendorCiscoASA,
		func() firewall.Ingestor { return New() },
		nil,
	)
}
