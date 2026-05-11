// Mappers from firewall payload types → wsproto.Observation rows.
//
// SubjectKey conventions: stable, parseable, and unique within (tenant,
// firewall, context). The fusion service in Chapter 4 will dedupe on these
// keys, so they must be deterministic — never include timestamps, sequence
// numbers, or anything else that varies between two ingests of the same
// firewall.
//
// Format: "ctx:<ctx>|<entity>:<natural-id>"
//
//	  ctx:vsys1|iface:port1
//	  ctx:root|route:vr=default,prefix=10.20.0.0/16,nh=10.0.0.1
//	  ctx:vsys1|vpn:HQ-to-Pune
//
// The "ctx:…" prefix lets a multi-context firewall keep two same-named
// objects (e.g. port1 in vsys1 vs vsys2) from colliding.
package firewall

import (
	"fmt"
	"time"

	"github.com/itom-mini/collector/internal/wsproto"
)

const (
	subjectInterface = "interface"
	subjectRoute     = "route"
	subjectArp       = "arp"
	subjectNatRule   = "nat_rule"
	subjectZone      = "zone"
	subjectPolicy    = "policy"
	subjectVpnTunnel = "vpn_tunnel"
	subjectBgpPeer   = "bgp_peer"
	subjectOspfPeer  = "ospf_peer"
)

// MapInterfaces turns each Interface row into one Observation.
func MapInterfaces(ctx Context, items []Interface, seenAt time.Time) []wsproto.Observation {
	out := make([]wsproto.Observation, 0, len(items))
	for _, it := range items {
		out = append(out, wsproto.Observation{
			SubjectKind: subjectInterface,
			SubjectKey:  fmt.Sprintf("ctx:%s|iface:%s", ctx.Name, it.Name),
			Attribute:   "config",
			Value: map[string]any{
				"name":      it.Name,
				"zone":      it.Zone,
				"status":    it.Status,
				"ips":       it.IPs,
				"mac":       it.MAC,
				"vlanId":    it.VlanID,
				"isVirtual": it.IsVirtual,
			},
			SeenAt: seenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func MapRoutes(ctx Context, items []Route, seenAt time.Time) []wsproto.Observation {
	out := make([]wsproto.Observation, 0, len(items))
	for _, r := range items {
		out = append(out, wsproto.Observation{
			SubjectKind: subjectRoute,
			SubjectKey: fmt.Sprintf(
				"ctx:%s|route:vr=%s,prefix=%s,nh=%s",
				ctx.Name, r.VirtualRouter, r.Prefix, r.NextHop,
			),
			Attribute: "config",
			Value: map[string]any{
				"virtualRouter": r.VirtualRouter,
				"prefix":        r.Prefix,
				"nextHop":       r.NextHop,
				"interface":     r.Interface,
				"protocol":      r.Protocol,
				"distance":      r.Distance,
				"metric":        r.Metric,
			},
			SeenAt: seenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func MapArp(ctx Context, items []ArpEntry, seenAt time.Time) []wsproto.Observation {
	out := make([]wsproto.Observation, 0, len(items))
	for _, a := range items {
		out = append(out, wsproto.Observation{
			SubjectKind: subjectArp,
			SubjectKey:  fmt.Sprintf("ctx:%s|arp:ip=%s", ctx.Name, a.IP),
			Attribute:   "alive",
			Value: map[string]any{
				"ip":        a.IP,
				"mac":       a.MAC,
				"interface": a.Interface,
			},
			SeenAt: seenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func MapNatRules(ctx Context, items []NatRule, seenAt time.Time) []wsproto.Observation {
	out := make([]wsproto.Observation, 0, len(items))
	for _, n := range items {
		out = append(out, wsproto.Observation{
			SubjectKind: subjectNatRule,
			SubjectKey:  fmt.Sprintf("ctx:%s|nat:%s", ctx.Name, n.Name),
			Attribute:   "config",
			Value: map[string]any{
				"name":           n.Name,
				"direction":      n.Direction,
				"originalSrc":    n.OriginalSrc,
				"originalDst":    n.OriginalDst,
				"originalPort":   n.OriginalPort,
				"protocol":       n.Protocol,
				"translatedSrc":  n.TranslatedSrc,
				"translatedDst":  n.TranslatedDst,
				"translatedPort": n.TranslatedPort,
			},
			SeenAt: seenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func MapZones(ctx Context, items []Zone, seenAt time.Time) []wsproto.Observation {
	out := make([]wsproto.Observation, 0, len(items))
	for _, z := range items {
		out = append(out, wsproto.Observation{
			SubjectKind: subjectZone,
			SubjectKey:  fmt.Sprintf("ctx:%s|zone:%s", ctx.Name, z.Name),
			Attribute:   "config",
			Value: map[string]any{
				"name":       z.Name,
				"interfaces": z.Interfaces,
			},
			SeenAt: seenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func MapPolicies(ctx Context, items []Policy, seenAt time.Time) []wsproto.Observation {
	out := make([]wsproto.Observation, 0, len(items))
	for _, p := range items {
		out = append(out, wsproto.Observation{
			SubjectKind: subjectPolicy,
			SubjectKey:  fmt.Sprintf("ctx:%s|policy:%s", ctx.Name, p.Name),
			Attribute:   "config",
			Value: map[string]any{
				"name":         p.Name,
				"fromZone":     p.FromZone,
				"toZone":       p.ToZone,
				"sources":      p.Sources,
				"destinations": p.Destinations,
				"services":     p.Services,
				"action":       p.Action,
				"enabled":      p.Enabled,
			},
			SeenAt: seenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func MapVpnTunnels(ctx Context, items []VpnTunnel, seenAt time.Time) []wsproto.Observation {
	out := make([]wsproto.Observation, 0, len(items))
	for _, v := range items {
		out = append(out, wsproto.Observation{
			SubjectKind: subjectVpnTunnel,
			SubjectKey:  fmt.Sprintf("ctx:%s|vpn:%s", ctx.Name, v.Name),
			Attribute:   "config",
			Value: map[string]any{
				"name":          v.Name,
				"peerIp":        v.PeerIP,
				"localSubnets":  v.LocalSubnets,
				"remoteSubnets": v.RemoteSubnets,
				"status":        v.Status,
				"ikeVersion":    v.IKEVersion,
			},
			SeenAt: seenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func MapBgpNeighbors(ctx Context, items []BgpNeighbor, seenAt time.Time) []wsproto.Observation {
	out := make([]wsproto.Observation, 0, len(items))
	for _, b := range items {
		out = append(out, wsproto.Observation{
			SubjectKind: subjectBgpPeer,
			SubjectKey:  fmt.Sprintf("ctx:%s|bgp:peer=%s", ctx.Name, b.PeerIP),
			Attribute:   "session",
			Value: map[string]any{
				"peerIp":    b.PeerIP,
				"peerAs":    b.PeerAS,
				"localAs":   b.LocalAS,
				"state":     b.State,
				"uptimeSec": b.UptimeSec,
			},
			SeenAt: seenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func MapOspfNeighbors(ctx Context, items []OspfNeighbor, seenAt time.Time) []wsproto.Observation {
	out := make([]wsproto.Observation, 0, len(items))
	for _, o := range items {
		out = append(out, wsproto.Observation{
			SubjectKind: subjectOspfPeer,
			SubjectKey:  fmt.Sprintf("ctx:%s|ospf:router=%s", ctx.Name, o.PeerRouterID),
			Attribute:   "session",
			Value: map[string]any{
				"peerRouterId": o.PeerRouterID,
				"area":         o.Area,
				"state":        o.State,
				"interface":    o.Interface,
			},
			SeenAt: seenAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}
