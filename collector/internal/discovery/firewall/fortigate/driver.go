package fortigate

import (
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Factory matches device.Factory so the registry can register us.
// Adapter logic (Login → ListContexts → Get* → emit observations →
// harvest neighbour hints) lives once in firewall.GenericDriver; this
// file is just the wiring.
func Factory() device.Driver {
	return firewall.NewGenericDriver(
		device.VendorFortiGate,
		func() firewall.Ingestor { return New() },
		nil, // FortiGate chassis-id extraction is a future polish PR
	)
}
