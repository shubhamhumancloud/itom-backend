package walkers

import (
	"strconv"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// CdpNeighbour is one row of CISCO-CDP-MIB::cdpCacheTable. Same idea
// as LLDP, Cisco-only protocol, often the only neighbour-discovery
// available because Cisco shops disable LLDP "for security."
//
// Index: cdpCacheIfIndex.cdpCacheDeviceIndex
type CdpNeighbour struct {
	LocalIfIndex int    // dot1dBasePort space... actually it's ifIndex here
	PeerDeviceID string // peer hostname (sometimes serial number)
	PeerAddress  string // management IP (decoded from PeerAddrType+Address)
	PeerPort     string // peer-side port name
	PeerVersion  string
	PeerPlatform string // "cisco WS-C3650-24TS"
}

// ReadCdp walks cdpCacheTable. Address decoding is non-trivial because
// the address is a raw OctetString whose length depends on
// cdpCacheAddressType (1 = ipv4 → 4 bytes).
func ReadCdp(c snmp.Runner) ([]CdpNeighbour, error) {
	deviceIDs, err := c.WalkTable(snmp.OIDCdpCacheDeviceId)
	if err != nil {
		return nil, nil
	}
	addrTypes, _ := c.WalkTable(snmp.OIDCdpCacheAddressType)
	addrs, _ := c.WalkTable(snmp.OIDCdpCacheAddress)
	ports, _ := c.WalkTable(snmp.OIDCdpCacheDevicePort)
	versions, _ := c.WalkTable(snmp.OIDCdpCacheVersion)
	platforms, _ := c.WalkTable(snmp.OIDCdpCachePlatform)

	out := make([]CdpNeighbour, 0, len(deviceIDs))
	for suffix, dv := range deviceIDs {
		parts := splitSuffix(suffix)
		if len(parts) < 1 {
			continue
		}
		ifIndex, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		ip := decodeCdpAddress(addrTypes[suffix].AsInt(), addrs[suffix].AsBytes())
		out = append(out, CdpNeighbour{
			LocalIfIndex: ifIndex,
			PeerDeviceID: dv.AsString(),
			PeerAddress:  ip,
			PeerPort:     ports[suffix].AsString(),
			PeerVersion:  versions[suffix].AsString(),
			PeerPlatform: platforms[suffix].AsString(),
		})
	}
	return out, nil
}

// decodeCdpAddress turns (addressType=1, bytes=[10,0,0,1]) into "10.0.0.1".
// Returns "" for unknown types or short byte arrays.
func decodeCdpAddress(addrType int64, b []byte) string {
	if addrType == 1 && len(b) == 4 { // ipv4
		return strconv.Itoa(int(b[0])) + "." +
			strconv.Itoa(int(b[1])) + "." +
			strconv.Itoa(int(b[2])) + "." +
			strconv.Itoa(int(b[3]))
	}
	return ""
}
