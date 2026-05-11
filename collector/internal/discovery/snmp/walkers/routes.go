package walkers

import (
	"fmt"
	"strconv"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// Route is one row from the device's routing table.
type Route struct {
	Prefix    string // "10.20.0.0/16"
	NextHop   string // gateway IP (or "" for connected)
	IfIndex   int    // outgoing interface
	Protocol  string // "local" | "static" | "bgp" | "ospf" | "rip" | "other"
	Type      string // "direct" | "indirect" | "reject"
}

// ReadRoutes walks IP-FORWARD-MIB::inetCidrRouteTable. The index is
// huge:
//   <destAddrType>.<destAddrLen>.<destAddr>.
//   <destPrefixLen>.<policy>.<nextHopAddrType>.<nextHopAddrLen>.<nextHopAddr>
//
// We slice it apart to recover destination + prefix length + next hop.
func ReadRoutes(c snmp.Runner) ([]Route, error) {
	ifIndices, err := c.WalkTable(snmp.OIDInetCidrRouteIfIndex)
	if err != nil {
		return nil, nil
	}
	types, _ := c.WalkTable(snmp.OIDInetCidrRouteType)
	protos, _ := c.WalkTable(snmp.OIDInetCidrRouteProto)

	out := make([]Route, 0, len(ifIndices))
	for suffix, iv := range ifIndices {
		parts := splitSuffix(suffix)
		// destAddrType + destAddrLen + addrBytes...
		dest, consumed := inetAddressFromSuffix(parts)
		if dest == "" {
			continue
		}
		if len(parts) <= consumed {
			continue
		}
		prefixLen, err := strconv.Atoi(parts[consumed])
		if err != nil {
			continue
		}
		// Skip policy (1 element).
		next := consumed + 1 + 1
		if len(parts) <= next {
			continue
		}
		nh, _ := inetAddressFromSuffix(parts[next:])
		out = append(out, Route{
			Prefix:   fmt.Sprintf("%s/%d", dest, prefixLen),
			NextHop:  nh,
			IfIndex:  int(iv.AsInt()),
			Protocol: routeProto(protos[suffix].AsInt()),
			Type:     routeType(types[suffix].AsInt()),
		})
	}
	return out, nil
}

// ReadRoutesLegacy walks the IPv4-only ipCidrRouteTable. Falls back
// here when the inet table is empty.
func ReadRoutesLegacy(c snmp.Runner) ([]Route, error) {
	ifIndices, err := c.WalkTable(snmp.OIDIpCidrRouteIfIndex)
	if err != nil {
		return nil, nil
	}
	types, _ := c.WalkTable(snmp.OIDIpCidrRouteType)
	protos, _ := c.WalkTable(snmp.OIDIpCidrRouteProto)

	out := make([]Route, 0, len(ifIndices))
	for suffix, iv := range ifIndices {
		// Index: <destIPv4>.<destMaskIPv4>.<tos>.<nextHopIPv4>
		parts := splitSuffix(suffix)
		if len(parts) < 13 {
			continue
		}
		dest, ok := ipv4FromSuffix(parts[0:4])
		if !ok {
			continue
		}
		mask, ok := ipv4FromSuffix(parts[4:8])
		if !ok {
			continue
		}
		nh, _ := ipv4FromSuffix(parts[9:13])
		out = append(out, Route{
			Prefix:   fmt.Sprintf("%s/%d", dest, maskToBits(mask)),
			NextHop:  nh,
			IfIndex:  int(iv.AsInt()),
			Protocol: routeProto(protos[suffix].AsInt()),
			Type:     routeType(types[suffix].AsInt()),
		})
	}
	return out, nil
}

func routeProto(n int64) string {
	switch n {
	case 2:
		return "local"
	case 3:
		return "netmgmt"
	case 4:
		return "icmp"
	case 8:
		return "rip"
	case 13:
		return "ospf"
	case 14:
		return "bgp"
	case 16:
		return "static"
	default:
		return "other"
	}
}

func routeType(n int64) string {
	switch n {
	case 3:
		return "direct"
	case 4:
		return "indirect"
	case 2:
		return "reject"
	default:
		return ""
	}
}

// maskToBits turns "255.255.0.0" into 16.
func maskToBits(mask string) int {
	bits := 0
	for i, p := range []byte(mask) {
		// Quick path: count ones from each octet. We split manually to
		// avoid a strings.Split allocation on a hot path.
		_ = i
		_ = p
	}
	// Simple implementation: parse octets, popcount each.
	var octets [4]int
	n, err := fmt.Sscanf(mask, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3])
	if err != nil || n != 4 {
		return 0
	}
	for _, o := range octets {
		for o > 0 {
			bits += o & 1
			o >>= 1
		}
	}
	return bits
}
