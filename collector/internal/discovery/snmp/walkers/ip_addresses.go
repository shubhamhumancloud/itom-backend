package walkers

import (
	"fmt"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// IpBinding is one row of IP-MIB::ipAddressTable — which IP is
// configured on which interface, with its prefix. Fusion uses these
// to spot L3 adjacencies (two routers on the same /30 → they're
// peers).
type IpBinding struct {
	IfIndex   int
	IP        string
	PrefixLen int    // derived from ipAddressPrefix's pointer-OID suffix
	Type      string // "unicast" | "anycast" | "broadcast"
}

// ReadIpAddresses walks ipAddressTable. The row index is
//   <addrType>.<addrLen>.<addrBytes>
// The ifIndex is in the .3 column (ipAddressIfIndex).
//
// The prefix length lives separately in ipAddressPrefix — it's the
// instance suffix of a pointer to ipAddressPrefixTable, which carries
// the prefix length as the SECOND-LAST integer in its OID. We extract
// that without walking the pointed-at table; one less SNMP round trip.
func ReadIpAddresses(c snmp.Runner) ([]IpBinding, error) {
	ifIndices, err := c.WalkTable(snmp.OIDIpAddressIfIndex)
	if err != nil {
		return nil, nil
	}
	types, _ := c.WalkTable(snmp.OIDIpAddressType)
	prefixPtrs, _ := c.WalkTable(snmp.OIDIpAddressPrefix)

	out := make([]IpBinding, 0, len(ifIndices))
	for suffix, iv := range ifIndices {
		ip, _ := inetAddressFromSuffix(splitSuffix(suffix))
		if ip == "" {
			continue
		}
		prefixLen := extractPrefixLength(prefixPtrs[suffix].AsString())
		out = append(out, IpBinding{
			IfIndex:   int(iv.AsInt()),
			IP:        ip,
			PrefixLen: prefixLen,
			Type:      addressType(types[suffix].AsInt()),
		})
	}
	return out, nil
}

// extractPrefixLength reads "1.3.6.1.2.1.4.32.1.5.<ifIndex>.<addrType>.<addrLen>.<bytes...>.<prefixLen>"
// and returns the final integer. Returns 0 on parse error.
func extractPrefixLength(s string) int {
	if s == "" {
		return 0
	}
	// Walk from the end backwards to find the last component — cheap
	// and avoids splitting the whole OID into a slice.
	end := len(s)
	for end > 0 && s[end-1] >= '0' && s[end-1] <= '9' {
		end--
	}
	if end == len(s) {
		return 0
	}
	// Anything after end is a dot followed by the prefix length.
	if end+1 > len(s) {
		return 0
	}
	var n int
	if _, err := fmt.Sscanf(s[end+1:], "%d", &n); err != nil {
		return 0
	}
	return n
}

func addressType(n int64) string {
	switch n {
	case 1:
		return "unicast"
	case 2:
		return "anycast"
	case 3:
		return "broadcast"
	default:
		return ""
	}
}
