package walkers

import (
	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// Interface is one port on the device.
//
// Two MIB tables describe the same set of interfaces:
//   - IF-MIB::ifTable     (the original, includes the 32-bit ifSpeed
//     that wraps at 4 Gbps and the awkward ifDescr "GigabitEthernet1/0/1")
//   - IF-MIB::ifXTable    (extensions, includes ifHighSpeed in Mbps and
//     ifName which is the short form "Gi1/0/1")
// We walk both and merge by ifIndex.
type Interface struct {
	Index       int
	Name        string // prefer ifName from ifXTable; fall back to ifDescr
	Description string // ifDescr — long form
	Alias       string // ifAlias — operator-set description ("uplink to coreR")
	Type        int    // ifType — IANA assigned (6=ethernet, 53=vlan, ...)
	Speed       uint64 // bits/sec, normalised from ifHighSpeed or ifSpeed
	MAC         string // ifPhysAddress
	AdminStatus string // up | down | testing | unknown
	OperStatus  string // up | down | testing | unknown | dormant | notPresent | lowerLayerDown
}

func ReadInterfaces(c snmp.Runner) ([]Interface, error) {
	descr, err := c.WalkTable(snmp.OIDIfDescr)
	if err != nil {
		return nil, err
	}
	// All other walks are best-effort — a switch missing ifAlias is
	// still useful, missing ifHighSpeed just means slower link speeds.
	ifType, _ := c.WalkTable(snmp.OIDIfType)
	speed, _ := c.WalkTable(snmp.OIDIfSpeed)
	highSpeed, _ := c.WalkTable(snmp.OIDIfHighSpeed)
	phys, _ := c.WalkTable(snmp.OIDIfPhysAddress)
	admin, _ := c.WalkTable(snmp.OIDIfAdminStatus)
	oper, _ := c.WalkTable(snmp.OIDIfOperStatus)
	ifName, _ := c.WalkTable(snmp.OIDIfName)
	alias, _ := c.WalkTable(snmp.OIDIfAlias)

	out := make([]Interface, 0, len(descr))
	for suffix, dv := range descr {
		idx, ok := parseIntSuffix(suffix)
		if !ok {
			continue
		}
		// Speed: ifHighSpeed (Mbps, 64-bit) preferred. Multiply to bps;
		// fall back to ifSpeed (bps, 32-bit) when ifHighSpeed=0.
		var bps uint64
		if hs := highSpeed[suffix].AsInt(); hs > 0 {
			bps = uint64(hs) * 1_000_000
		} else if s := speed[suffix].AsInt(); s > 0 {
			bps = uint64(s)
		}
		name := ifName[suffix].AsString()
		if name == "" {
			name = dv.AsString()
		}
		out = append(out, Interface{
			Index:       idx,
			Name:        name,
			Description: dv.AsString(),
			Alias:       alias[suffix].AsString(),
			Type:        int(ifType[suffix].AsInt()),
			Speed:       bps,
			MAC:         phys[suffix].AsMAC(),
			AdminStatus: ifStatus(admin[suffix].AsInt()),
			OperStatus:  ifStatus(oper[suffix].AsInt()),
		})
	}
	return out, nil
}

// ifStatus maps RFC 2863 ifOperStatus / ifAdminStatus integers to
// strings the dashboard can render directly.
func ifStatus(n int64) string {
	switch n {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 4:
		return "unknown"
	case 5:
		return "dormant"
	case 6:
		return "notPresent"
	case 7:
		return "lowerLayerDown"
	default:
		return ""
	}
}
