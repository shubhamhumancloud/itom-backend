package sophos

import (
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Factory wires the Sophos Firewall XML API Ingestor into the
// dispatcher's driver registry via the shared firewall.GenericDriver
// adapter.
func Factory() device.Driver {
	return firewall.NewGenericDriver(
		device.VendorSophos,
		func() firewall.Ingestor { return New() },
		nil,
	)
}
