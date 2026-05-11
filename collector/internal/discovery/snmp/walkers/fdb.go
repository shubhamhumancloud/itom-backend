package walkers

import (
	"strconv"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// FdbEntry is one MAC ↔ port row from the switch's forwarding table.
// Joined with ArpEntry by MAC (in fusion), this places a host onto a
// specific switch port.
type FdbEntry struct {
	VlanID  int    // 0 if not VLAN-aware (legacy dot1d table)
	MAC     string
	IfIndex int    // resolved via dot1dBasePortIfIndex
	Status  string // "learned" | "self" | "mgmt" | "invalid" | "other"
}

// ReadFdb prefers Q-BRIDGE-MIB::dot1qTpFdbTable (VLAN-aware).
//
// NOTE: On Cisco IOS / IOS-XE, an SNMPv2c walk against this table
// returns ONLY entries from the native VLAN unless the community
// string is suffixed with "@<vlan-id>" — see the chapter-2 doc. This
// is deferred to a polish PR; the first cut emits native-VLAN MACs
// only and the operator dashboard will surface the gap.
func ReadFdb(c snmp.Runner) ([]FdbEntry, error) {
	ports, err := c.WalkTable(snmp.OIDDot1qTpFdbPort)
	if err != nil {
		return nil, nil
	}
	statuses, _ := c.WalkTable(snmp.OIDDot1qTpFdbStatus)
	portToIf, _ := c.WalkTable(snmp.OIDDot1dBasePortIfIndex)

	out := make([]FdbEntry, 0, len(ports))
	for suffix, pv := range ports {
		// Index: fdbId.<6-octet MAC as dotted decimals>
		parts := splitSuffix(suffix)
		if len(parts) != 7 {
			continue
		}
		vlan, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		mac := macFromDecOctets(parts[1:7])
		if mac == "" {
			continue
		}
		basePort := pv.AsInt()
		ifIdx := int(portToIf[strconv.FormatInt(basePort, 10)].AsInt())
		out = append(out, FdbEntry{
			VlanID:  vlan,
			MAC:     mac,
			IfIndex: ifIdx,
			Status:  fdbStatus(statuses[suffix].AsInt()),
		})
	}
	return out, nil
}

// ReadFdbLegacy walks BRIDGE-MIB::dot1dTpFdbTable — VLAN-unaware.
// Used when the modern table is absent (rare on modern gear).
func ReadFdbLegacy(c snmp.Runner) ([]FdbEntry, error) {
	ports, err := c.WalkTable(snmp.OIDDot1dTpFdbPort)
	if err != nil {
		return nil, nil
	}
	statuses, _ := c.WalkTable(snmp.OIDDot1dTpFdbStatus)
	portToIf, _ := c.WalkTable(snmp.OIDDot1dBasePortIfIndex)

	out := make([]FdbEntry, 0, len(ports))
	for suffix, pv := range ports {
		parts := splitSuffix(suffix)
		if len(parts) != 6 {
			continue
		}
		mac := macFromDecOctets(parts)
		if mac == "" {
			continue
		}
		basePort := pv.AsInt()
		ifIdx := int(portToIf[strconv.FormatInt(basePort, 10)].AsInt())
		out = append(out, FdbEntry{
			VlanID:  0,
			MAC:     mac,
			IfIndex: ifIdx,
			Status:  fdbStatus(statuses[suffix].AsInt()),
		})
	}
	return out, nil
}

func fdbStatus(n int64) string {
	switch n {
	case 1:
		return "other"
	case 2:
		return "invalid"
	case 3:
		return "learned"
	case 4:
		return "self"
	case 5:
		return "mgmt"
	default:
		return ""
	}
}
