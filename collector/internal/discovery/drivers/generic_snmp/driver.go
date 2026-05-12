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

	"github.com/gosnmp/gosnmp"

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
	if !creds.HasSNMP() {
		return device.IngestResult{}, &device.ErrAuth{
			Wrapped: errors.New("generic_snmp: SNMP credential (v2c community or v3 username) required"),
		}
	}

	c, err := openSNMP(ctx, creds, "")
	if err != nil {
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

	// 8. FDB — switch's MAC↔port table. On Cisco IOS / IOS-XE a plain
	// v2c walk returns only the native VLAN's MACs; we use the
	// per-VLAN community trick to see every VLAN. Detection is by
	// sysObjectID prefix (Cisco = 1.3.6.1.4.1.9).
	fdb := collectFDB(ctx, c, creds, sys.ObjectID)
	for _, f := range fdb {
		res.Observations = append(res.Observations, wsproto.Observation{
			SubjectKind: "fdb",
			SubjectKey:  fmt.Sprintf("chassis:%s|fdb:%s|vlan:%d", chassisID, f.MAC, f.VlanID),
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

// isCisco returns true if the device's sysObjectID is under Cisco's
// enterprise OID (1.3.6.1.4.1.9). Only Cisco IOS / IOS-XE needs the
// per-VLAN trick — NX-OS and most non-Cisco gear expose VLAN-aware
// data through Q-BRIDGE-MIB directly.
func isCisco(sysObjectID string) bool {
	return strings.HasPrefix(sysObjectID, "1.3.6.1.4.1.9.") ||
		strings.HasPrefix(sysObjectID, ".1.3.6.1.4.1.9.")
}

// collectFDB does the standard FDB walk plus, on Cisco IOS, one
// re-walk per VLAN with the per-VLAN community/context trick. Results
// are unioned by (vlan, MAC).
//
// Why a wrapper function: keeps the main Ingest body readable; the
// Cisco quirk lives in one named place.
func collectFDB(
	ctx context.Context,
	c *snmp.Client,
	creds device.Creds,
	sysObjectID string,
) []walkers.FdbEntry {
	// Default path — Q-BRIDGE first, legacy dot1d fallback.
	base, _ := walkers.ReadFdb(c)
	if len(base) == 0 {
		base, _ = walkers.ReadFdbLegacy(c)
	}
	if !isCisco(sysObjectID) {
		return base
	}

	// Cisco path. Enumerate VLANs and re-walk per VLAN.
	vlans, _ := walkers.ReadVlans(c)
	if len(vlans) == 0 {
		return base
	}

	// Dedup key: vlanId + MAC. The base walk already saw native-VLAN
	// rows; keep those, add any new rows we discover under specific
	// VLAN contexts.
	type key struct {
		vlan int
		mac  string
	}
	seen := map[key]bool{}
	out := make([]walkers.FdbEntry, 0, len(base))
	for _, f := range base {
		seen[key{f.VlanID, f.MAC}] = true
		out = append(out, f)
	}
	for _, v := range vlans {
		if v.State != "operational" || v.ID == 0 || v.ID == 1002 || v.ID == 1003 || v.ID == 1004 || v.ID == 1005 {
			// Skip default (1) is intentionally NOT skipped — we
			// already saw VLAN 1's MACs in the base walk. The 1002-
			// 1005 range is Cisco's reserved token-ring/FDDI VLANs
			// (always there, never useful).
			continue
		}
		ctxSnmp, err := openSNMP(ctx, creds, fmt.Sprintf("@%d", v.ID))
		if err != nil {
			// Bad credential for this VLAN context, or device blocks
			// it — skip silently. Other VLANs may still work.
			continue
		}
		rows, _ := walkers.ReadFdb(ctxSnmp)
		ctxSnmp.Close()
		for _, f := range rows {
			// The walker reads vlanId from the OID suffix, but in a
			// per-VLAN-community walk the suffix may collapse — force
			// our context VLAN onto the row so the dedup key is correct.
			f.VlanID = v.ID
			k := key{f.VlanID, f.MAC}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

// openSNMP picks v2c or v3 from creds and returns a session, mapping
// snmp.* error types to device.* error types so the crawl classifier
// sees uniform shapes regardless of which SNMP version we tried.
//
// vlanSuffix (e.g. "@10") is appended to a v2c community for the Cisco
// per-VLAN FDB trick. On v3 we use ContextName="vlan-10" instead.
func openSNMP(ctx context.Context, creds device.Creds, vlanSuffix string) (*snmp.Client, error) {
	cfg := snmp.Config{Target: creds.Host}
	if creds.SNMPv3Username != "" {
		cfg.Version = gosnmp.Version3
		cfg.V3 = snmp.V3Config{
			Username:     creds.SNMPv3Username,
			AuthProtocol: creds.SNMPv3AuthProtocol,
			AuthKey:      creds.SNMPv3AuthKey,
			PrivProtocol: creds.SNMPv3PrivProtocol,
			PrivKey:      creds.SNMPv3PrivKey,
		}
		if vlanSuffix != "" {
			// "@10" → "vlan-10" — gosnmp passes ContextName through to
			// the agent which scopes the read.
			cfg.ContextName = "vlan-" + strings.TrimPrefix(vlanSuffix, "@")
		}
	} else {
		cfg.Version = gosnmp.Version2c
		cfg.Community = creds.SNMPCommunity + vlanSuffix
	}
	c, err := snmp.Open(ctx, cfg)
	if err != nil {
		if snmp.IsAuth(err) {
			return nil, &device.ErrAuth{Wrapped: err}
		}
		if snmp.IsUnreachable(err) || snmp.IsTimeout(err) {
			return nil, &device.ErrUnreachable{Wrapped: err}
		}
		return nil, err
	}
	return c, nil
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
