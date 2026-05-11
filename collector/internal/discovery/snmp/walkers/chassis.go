package walkers

import (
	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// Chassis is the row of entPhysicalTable that describes the physical
// device. Walking entPhysicalTable returns one row per hardware
// component (line card, transceiver, ...); we only care about the
// chassis-class row (entPhysicalClass=3).
type Chassis struct {
	Serial      string
	Model       string
	Description string
}

// ReadChassis returns the first chassis-class row, or an empty Chassis
// if entPhysicalTable isn't populated. The empty case is common on
// small / older gear; the driver then falls back to lldpLocChassisId
// and finally to sysName as a synthetic key.
func ReadChassis(c snmp.Runner) (Chassis, error) {
	classes, err := c.WalkTable(snmp.OIDEntPhysicalClass)
	if err != nil {
		return Chassis{}, nil
	}
	if len(classes) == 0 {
		return Chassis{}, nil
	}
	descrs, _ := c.WalkTable(snmp.OIDEntPhysicalDescr)
	serials, _ := c.WalkTable(snmp.OIDEntPhysicalSerialNum)
	models, _ := c.WalkTable(snmp.OIDEntPhysicalModelName)

	for suffix, cv := range classes {
		if cv.AsInt() == snmp.EntClassChassis {
			s := serials[suffix].AsString()
			if s == "" {
				// Some Cisco platforms put the serial in a child row
				// labelled "Chassis 1" — but the first chassis-class
				// row's serial is the authoritative one we trust as a
				// dedup key. Leave empty here; the driver will fall
				// back.
				continue
			}
			return Chassis{
				Serial:      s,
				Model:       models[suffix].AsString(),
				Description: descrs[suffix].AsString(),
			}, nil
		}
	}
	return Chassis{}, nil
}

// ReadLldpLocalChassisID is the fallback used by the driver when
// entPhysicalTable doesn't expose a serial. lldpLocChassisId is a
// scalar (".0") that virtually every LLDP-capable device exposes.
func ReadLldpLocalChassisID(c snmp.Runner) (string, error) {
	res, err := c.Get([]string{snmp.OIDLldpLocChassisId + ".0"})
	if err != nil {
		return "", err
	}
	return res[snmp.OIDLldpLocChassisId+".0"].AsString(), nil
}
