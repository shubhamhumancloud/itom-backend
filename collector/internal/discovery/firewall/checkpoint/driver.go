package checkpoint

import (
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Factory wires the Check Point Management API Ingestor into the
// dispatcher's driver registry via the shared firewall.GenericDriver
// adapter.
func Factory() device.Driver {
	return firewall.NewGenericDriver(
		device.VendorCheckPoint,
		func() firewall.Ingestor { return New() },
		nil,
	)
}
