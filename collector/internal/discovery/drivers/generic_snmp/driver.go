// Package generic_snmp implements device.Driver against any SNMPv2c
// device. Reads the standard MIBs (system, interfaces, LLDP, CDP, ARP,
// FDB, routes, ipAddress, entPhysical) and emits one observation per
// row plus neighbour hints harvested from LLDP and CDP for the crawl
// to enqueue.
//
// Cisco-specific quirks live here too — the FDB walk on Cisco IOS
// needs the per-VLAN community trick, which is deferred (see the
// chapter-2 doc and walkers/fdb.go). When we add it, only this file
// changes.
package generic_snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/snmp"
	"github.com/itom-mini/collector/internal/discovery/snmp/walkers"
	"github.com/itom-mini/collector/internal/wsproto"
)

// Driver implements device.Driver via SNMPv2c. Stateless; one fresh
// session per Ingest call.
type Driver struct{}

// NewDriver returns a new Driver instance.
func NewDriver() device.Driver { return &Driver{} }

// Factory matches device.Factory so the registry can register us.
func Factory() device.Driver { return NewDriver() }

func (d *Driver) Vendor() device.Vendor { return device.VendorGenericSNMP }

func (d *Driver) Ingest(ctx context.Context, creds device.Creds) (device.IngestResult, error) {
	if creds.SNMPCommunity == "" {
		return device.IngestResult{}, &device.ErrAuth{
			Wrapped: errors.New("generic_snmp: SNMP community required"),
		}
	}

	c, err := snmp.Open(ctx, snmp.Config{
		Target:    creds.Host,
		Community: creds.SNMPCommunity,
	})
	if err != nil {
		// Map snmp.* errors to device.* errors so the dispatcher can
		// classify uniformly.
		if snmp.IsAuth(err) {
			return device.IngestResult{}, &device.ErrAuth{Wrapped: err}
		}
		if snmp.IsUnreachable(err) || snmp.IsTimeout(err) {
			return device.IngestResult{}, &device.ErrUnreachable{Wrapped: err}
		}
		return device.IngestResult{}, err
	}
	defer c.Close()

	now := time.Now().UTC()
	res := device.IngestResult{}

	// 1. System info — drives the dedup key and the human label.
	sys, err := walkers.ReadSystem(c)
	if err != nil {
		return res, fmt.Errorf("read system: %w", err)
	}

	// 2. Chassis serial via entPhysicalTable, fall back to lldpLocChassisId,
	// finally to sysName so dedup still has SOMETHING to key off.
	chassis, _ := walkers.ReadChassis(c)
	chassisID := chassis.Serial
	if chassisID == "" {
		if lldpID, err := walkers.ReadLldpLocalChassisID(c); err == nil && lldpID != "" {
			chassisID = lldpID
		}
	}
	if chassisID == "" {
		chassisID = "sysname:" + sys.Name
	}
	res.ChassisID = chassisID

	// One device-summary observation up front. Carries the vendor
	// label we settled on, sysObjectID (for fingerprint cross-check),
	// and the chassis identity. The crawler's emitted-fingerprint
	// observation already covers probe evidence; this is the
	// SNMP-side authoritative record.
	res.Observations = append(res.Observations, wsproto.Observation{
		SubjectKind: "device",
		SubjectKey:  "chassis:" + chassisID,
		Attribute:   "snmp_identity",
		Value: map[string]any{
			"sysName":      sys.Name,
			"sysDescr":     sys.Description,
			"sysObjectId":  sys.ObjectID,
			"sysLocation":  sys.Location,
			"sysUpTime":    sys.Uptime,
			"chassisId":    chassisID,
			"chassisSerial": chassis.Serial,
			"chassisModel": chassis.Model,
			"managementIp": creds.Host,
		},
		SeenAt: ts(now),
	})

	// 3. Interfaces.
	ifs, err := walkers.ReadInterfaces(c)
	if err != nil {
		return res, fmt.Errorf("read interfaces: %w", err)
	}
	ifByIndex := make(map[int]walkers.Interface, len(ifs))
	for _, it := range ifs {
		ifByIndex[it.Index] = it
		res.Observations = append(res.Observations, wsproto.Observation{
			SubjectKind: "interface",
			SubjectKey:  fmt.Sprintf("chassis:%s|if:%d", chassisID, it.Index),
			Attribute:   "config",
			Value: map[string]any{
				"index":       it.Index,
				"name":        it.Name,
				"description": it.Description,
				"alias":       it.Alias,
				"type":        it.Type,
				"speedBps":    it.Speed,
				"mac":         it.MAC,
				"adminStatus": it.AdminStatus,
				"operStatus":  it.OperStatus,
			},
			SeenAt: ts(now),
		})
	}

	// 4. IP bindings — which IPs live on which interfaces.
	ips, _ := walkers.ReadIpAddresses(c)
	for _, b := range ips {
		res.Observations = append(res.Observations, wsproto.Observation{
			SubjectKind: "ip_binding",
			SubjectKey:  fmt.Sprintf("chassis:%s|if:%d|ip:%s", chassisID, b.IfIndex, b.IP),
			Attribute:   "config",
			Value: map[string]any{
				"ifIndex":   b.IfIndex,
				"ip":        b.IP,
				"prefixLen": b.PrefixLen,
				"type":      b.Type,
			},
			SeenAt: ts(now),
		})
	}

	// 5. LLDP neighbours — primary topology edges + new seeds.
	lldp, _ := walkers.ReadLldp(c)
	lldpMgmt, _ := walkers.ReadLldpManagementAddresses(c)
	for _, n := range lldp {
		// Resolve local port number → ifIndex when we know how. On
		// most modern gear the LLDP local port equals the ifIndex
		// directly; some platforms use the dot1dBasePort space and
		// would need the BridgeBaseTable join. We pass the raw
		// number through and let fusion sort it out.
		res.Observations = append(res.Observations, wsproto.Observation{
			SubjectKind: "link",
			SubjectKey: fmt.Sprintf(
				"chassis:%s|port:%d|peer-chassis:%s",
				chassisID, n.LocalPortNum, safeKey(n.PeerChassisID),
			),
			Attribute: "lldp",
			Value: map[string]any{
				"localChassisId": chassisID,
				"localPort":      n.LocalPortNum,
				"peerChassisId":  n.PeerChassisID,
				"peerPortId":     n.PeerPortID,
				"peerPortDesc":   n.PeerPortDesc,
				"peerSysName":    n.PeerSysName,
				"peerSysDesc":    n.PeerSysDesc,
			},
			SeenAt: ts(now),
		})
		for _, ip := range lldpMgmt[n.LocalPortNum] {
			res.Neighbours = append(res.Neighbours, device.NeighbourHint{
				IP:     ip,
				Reason: "lldp_peer",
			})
		}
	}

	// 6. CDP neighbours — Cisco-private, but worth reading on every
	// device because non-Cisco gear returns NoSuchObject cheaply.
	cdp, _ := walkers.ReadCdp(c)
	for _, n := range cdp {
		res.Observations = append(res.Observations, wsproto.Observation{
			SubjectKind: "link",
			SubjectKey: fmt.Sprintf(
				"chassis:%s|if:%d|peer-device:%s",
				chassisID, n.LocalIfIndex, safeKey(n.PeerDeviceID),
			),
			Attribute: "cdp",
			Value: map[string]any{
				"localChassisId": chassisID,
				"localIfIndex":   n.LocalIfIndex,
				"peerDeviceId":   n.PeerDeviceID,
				"peerAddress":    n.PeerAddress,
				"peerPort":       n.PeerPort,
				"peerVersion":    n.PeerVersion,
				"peerPlatform":   n.PeerPlatform,
			},
			SeenAt: ts(now),
		})
		if n.PeerAddress != "" {
			res.Neighbours = append(res.Neighbours, device.NeighbourHint{
				IP:     n.PeerAddress,
				Reason: "cdp_peer",
			})
		}
	}

	// 7. ARP — IP↔MAC bindings the device currently knows. Try the
	// modern table first; if empty, fall back to the legacy one.
	arp, _ := walkers.ReadArp(c)
	if len(arp) == 0 {
		arp, _ = walkers.ReadArpLegacy(c)
	}
	for _, a := range arp {
		res.Observations = append(res.Observations, wsproto.Observation{
			SubjectKind: "arp",
			SubjectKey:  fmt.Sprintf("chassis:%s|arp:%s", chassisID, a.IP),
			Attribute:   "binding",
			Value: map[string]any{
				"ifIndex": a.IfIndex,
				"ip":      a.IP,
				"mac":     a.MAC,
				"type":    a.Type,
			},
			SeenAt: ts(now),
		})
		// Don't push ARP entries as crawl seeds by default — ARP
		// produces lots of host IPs (printers, laptops) that won't
		// have SNMP. The crawl picks them up only via LLDP/CDP/routes.
		// (We can revisit if a customer needs aggressive sweeping.)
	}

	// 8. FDB — switch's MAC↔port table. Modern Q-BRIDGE first;
	// legacy dot1d as fallback.
	fdb, _ := walkers.ReadFdb(c)
	if len(fdb) == 0 {
		fdb, _ = walkers.ReadFdbLegacy(c)
	}
	for _, f := range fdb {
		res.Observations = append(res.Observations, wsproto.Observation{
			SubjectKind: "fdb",
			SubjectKey:  fmt.Sprintf("chassis:%s|fdb:%s", chassisID, f.MAC),
			Attribute:   "entry",
			Value: map[string]any{
				"vlanId":  f.VlanID,
				"mac":     f.MAC,
				"ifIndex": f.IfIndex,
				"status":  f.Status,
			},
			SeenAt: ts(now),
		})
	}

	// 9. Routes — only L3 devices populate this; switches return
	// empty. We feed route next-hops back to the crawl as seeds.
	routes, _ := walkers.ReadRoutes(c)
	if len(routes) == 0 {
		routes, _ = walkers.ReadRoutesLegacy(c)
	}
	for _, r := range routes {
		res.Observations = append(res.Observations, wsproto.Observation{
			SubjectKind: "route",
			SubjectKey: fmt.Sprintf(
				"chassis:%s|route:%s,nh:%s", chassisID, r.Prefix, r.NextHop,
			),
			Attribute: "entry",
			Value: map[string]any{
				"prefix":   r.Prefix,
				"nextHop":  r.NextHop,
				"ifIndex":  r.IfIndex,
				"protocol": r.Protocol,
				"type":     r.Type,
			},
			SeenAt: ts(now),
		})
		// Indirect routes whose next-hop is reachable are good seeds.
		// Connected ("local" / "direct" / next-hop empty) routes are
		// not.
		if r.NextHop != "" && r.NextHop != "0.0.0.0" {
			res.Neighbours = append(res.Neighbours, device.NeighbourHint{
				IP:     r.NextHop,
				Reason: "route_next_hop",
			})
		}
	}

	return res, nil
}

// ts formats a fixed time as RFC3339Nano UTC — every observation
// emitted by one Ingest call carries the same timestamp so the chunk
// looks like a coherent snapshot.
func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// safeKey strips characters that would mangle our subjectKey
// pipe-delimited shape if a vendor smuggled them into a hostname or
// chassis id.
func safeKey(s string) string {
	s = strings.ReplaceAll(s, "|", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}
