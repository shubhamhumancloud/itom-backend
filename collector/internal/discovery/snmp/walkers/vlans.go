package walkers

import (
	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// Vlan describes one VLAN configured on a Cisco device.
type Vlan struct {
	ID    int
	State string // "operational" | "suspended" | "mtuTooBigForDevice" | "mtuTooBigForTrunk"
}

// ReadVlans walks vtpVlanState. Returns empty on non-Cisco devices
// (the OID is Cisco-private and other vendors return NoSuchObject).
// Used to drive the per-VLAN FDB walk — currently deferred (see fdb.go).
func ReadVlans(c snmp.Runner) ([]Vlan, error) {
	states, err := c.WalkTable(snmp.OIDVtpVlanState)
	if err != nil {
		return nil, nil
	}
	out := make([]Vlan, 0, len(states))
	for suffix, sv := range states {
		// Index: vtpVlanManagementDomainIndex.vtpVlanIndex — second
		// component is the actual VLAN ID.
		parts := splitSuffix(suffix)
		if len(parts) < 2 {
			continue
		}
		vid, ok := parseIntSuffix(parts[1])
		if !ok {
			continue
		}
		out = append(out, Vlan{
			ID:    vid,
			State: vlanState(sv.AsInt()),
		})
	}
	return out, nil
}

func vlanState(n int64) string {
	switch n {
	case 1:
		return "operational"
	case 2:
		return "suspended"
	case 3:
		return "mtuTooBigForDevice"
	case 4:
		return "mtuTooBigForTrunk"
	default:
		return ""
	}
}
