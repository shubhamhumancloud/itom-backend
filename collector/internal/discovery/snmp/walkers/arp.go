package walkers

import (
	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// ArpEntry is one IP↔MAC binding the device has cached. Joined with
// FDB rows (chapter-4 fusion), tells us which port a host is plugged
// into.
type ArpEntry struct {
	IfIndex int    // interface the binding was seen on
	IP      string
	MAC     string
	Type    string // "static" | "dynamic" | "local" | "other"
}

// ReadArp prefers the modern ipNetToPhysicalTable (IPv4 + IPv6).
// Returns an empty slice — never error — when the table is absent so
// the driver can fall back to the legacy table without confusion.
func ReadArp(c snmp.Runner) ([]ArpEntry, error) {
	macs, err := c.WalkTable(snmp.OIDIpNetToPhysicalPhysAddress)
	if err != nil {
		return nil, nil
	}
	types, _ := c.WalkTable(snmp.OIDIpNetToPhysicalType)

	out := make([]ArpEntry, 0, len(macs))
	for suffix, mv := range macs {
		// Index: ifIndex.<inetAddrType>.<inetAddrLen>.<bytes>
		parts := splitSuffix(suffix)
		if len(parts) < 3 {
			continue
		}
		ifIndex, ok := parseIntSuffix(parts[0])
		if !ok {
			continue
		}
		ip, _ := inetAddressFromSuffix(parts[1:])
		if ip == "" {
			continue
		}
		out = append(out, ArpEntry{
			IfIndex: ifIndex,
			IP:      ip,
			MAC:     mv.AsMAC(),
			Type:    arpType(types[suffix].AsInt()),
		})
	}
	return out, nil
}

// ReadArpLegacy walks the IPv4-only ipNetToMediaTable. We try this
// when ReadArp comes back empty — old IOS, some smaller appliances
// only populate the legacy table.
func ReadArpLegacy(c snmp.Runner) ([]ArpEntry, error) {
	macs, err := c.WalkTable(snmp.OIDIpNetToMediaPhysAddress)
	if err != nil {
		return nil, nil
	}
	out := make([]ArpEntry, 0, len(macs))
	for suffix, mv := range macs {
		// Index: ifIndex.ipv4-as-dotted
		parts := splitSuffix(suffix)
		if len(parts) < 5 {
			continue
		}
		ifIndex, ok := parseIntSuffix(parts[0])
		if !ok {
			continue
		}
		ip, ok := ipv4FromSuffix(parts[1:5])
		if !ok {
			continue
		}
		out = append(out, ArpEntry{
			IfIndex: ifIndex,
			IP:      ip,
			MAC:     mv.AsMAC(),
			Type:    "dynamic",
		})
	}
	return out, nil
}

func arpType(n int64) string {
	switch n {
	case 1:
		return "other"
	case 2:
		return "invalid"
	case 3:
		return "dynamic"
	case 4:
		return "static"
	case 5:
		return "local"
	default:
		return ""
	}
}
