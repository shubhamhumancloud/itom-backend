package walkers

import (
	"strconv"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// LldpNeighbour is one row of lldpRemTable — what a neighbour told us
// over a directly-attached link. This is the topology edge.
type LldpNeighbour struct {
	// LocalPortNum is the dot1dBasePort or ifIndex (varies by vendor)
	// of the local port that received the LLDP frame.
	LocalPortNum int
	// PeerChassisID is whatever the peer chose to identify itself —
	// usually its MAC, sometimes its sysName. The driver normalises.
	PeerChassisID string
	// PeerPortID is the peer's side of the cable.
	PeerPortID string
	PeerPortDesc string
	PeerSysName  string
	PeerSysDesc  string
}

// ReadLldp walks lldpRemTable. The row index is
//   lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex
// We only need the second component (the local port) for topology;
// the rest are bookkeeping.
func ReadLldp(c snmp.Runner) ([]LldpNeighbour, error) {
	chassis, err := c.WalkTable(snmp.OIDLldpRemChassisId)
	if err != nil {
		// Many devices simply don't have LLDP enabled. Treat empty as
		// "no data" rather than failure.
		return nil, nil
	}
	portIds, _ := c.WalkTable(snmp.OIDLldpRemPortId)
	portDescs, _ := c.WalkTable(snmp.OIDLldpRemPortDesc)
	sysNames, _ := c.WalkTable(snmp.OIDLldpRemSysName)
	sysDescs, _ := c.WalkTable(snmp.OIDLldpRemSysDesc)

	out := make([]LldpNeighbour, 0, len(chassis))
	for suffix, cv := range chassis {
		parts := splitSuffix(suffix)
		if len(parts) < 2 {
			continue
		}
		localPort, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		out = append(out, LldpNeighbour{
			LocalPortNum:  localPort,
			PeerChassisID: cv.AsString(),
			PeerPortID:    portIds[suffix].AsString(),
			PeerPortDesc:  portDescs[suffix].AsString(),
			PeerSysName:   sysNames[suffix].AsString(),
			PeerSysDesc:   sysDescs[suffix].AsString(),
		})
	}
	return out, nil
}

// ReadLldpManagementAddresses pulls the per-neighbour management IPs
// LLDP advertises — these are the IPs we feed back to the crawl
// queue as fresh seeds.
//
// Index shape: lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex.
//              lldpRemManAddrSubtype.lldpRemManAddrLen.<addrBytes>
// The address bytes are a v4 address (4 bytes) or v6 (16 bytes).
// Returns map[localPortNum] → list of IP strings.
func ReadLldpManagementAddresses(c snmp.Runner) (map[int][]string, error) {
	tab, err := c.WalkTable(snmp.OIDLldpRemManAddrIfId)
	if err != nil {
		return nil, nil
	}
	out := map[int][]string{}
	for suffix := range tab {
		parts := splitSuffix(suffix)
		if len(parts) < 6 {
			continue
		}
		localPort, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		// Strip lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex (3 parts)
		// then we're at lldpRemManAddrSubtype.lldpRemManAddrLen.<bytes...>.
		// Subtype 1 = ipv4, 2 = ipv6 (per RFC).
		addrType, _ := strconv.Atoi(parts[3])
		addrLen, _ := strconv.Atoi(parts[4])
		if len(parts) < 5+addrLen {
			continue
		}
		switch addrType {
		case 1: // ipv4
			ip, ok := ipv4FromSuffix(parts[5 : 5+addrLen])
			if ok && ip != "" {
				out[localPort] = append(out[localPort], ip)
			}
		case 2: // ipv6 — skipped for now; chapter 2 deliverable is v4
		}
	}
	return out, nil
}
