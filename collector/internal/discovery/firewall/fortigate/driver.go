package fortigate

import (
	"context"
	"time"

	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Driver wraps the existing FortiGate firewall.Ingestor and adapts it
// to the device.Driver contract. Two responsibilities on top of the
// Ingestor:
//   1. Map each firewall payload type → observations (delegating to
//      firewall.Map*).
//   2. Harvest neighbour hints from the same data — every route
//      next-hop, every BGP/OSPF peer, every VPN tunnel peer is a
//      candidate for the crawl queue.
type Driver struct{}

// NewDriver returns a Driver. Stateless — every Ingest call builds a
// fresh underlying Ingestor.
func NewDriver() device.Driver { return &Driver{} }

// Factory matches device.Factory so the registry can register us.
func Factory() device.Driver { return NewDriver() }

func (d *Driver) Vendor() device.Vendor { return device.VendorFortiGate }

func (d *Driver) Ingest(ctx context.Context, creds device.Creds) (device.IngestResult, error) {
	fcreds := firewall.Creds{
		Host:                 creds.Host,
		Username:             creds.Username,
		Password:             creds.Password,
		APIKey:               creds.APIKey,
		TLSFingerprintSHA256: creds.TLSFingerprintSHA256,
	}
	ing := New()
	if err := ing.Login(ctx, fcreds); err != nil {
		return device.IngestResult{}, err
	}
	defer func() { _ = ing.Logout() }()

	contexts, err := ing.ListContexts(ctx)
	if err != nil {
		return device.IngestResult{}, err
	}

	res := device.IngestResult{}
	seenNeighbour := map[string]bool{} // dedupe at this device
	addHint := func(ip, reason string) {
		if ip == "" || ip == "0.0.0.0" || ip == "::" {
			return
		}
		// One hint per (ip,reason) — duplicates flood the audit log
		// without adding signal.
		key := ip + "|" + reason
		if seenNeighbour[key] {
			return
		}
		seenNeighbour[key] = true
		res.Neighbours = append(res.Neighbours, device.NeighbourHint{
			IP: ip, Reason: reason,
		})
	}

	now := time.Now().UTC()
	for _, c := range contexts {
		if err := ctx.Err(); err != nil {
			return res, err
		}

		ifaces, err := softFail(ing.GetInterfaces(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations,
			firewall.MapInterfaces(c, ifaces, now)...)

		routes, err := softFail(ing.GetRoutes(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations,
			firewall.MapRoutes(c, routes, now)...)
		for _, r := range routes {
			// Skip connected routes (next-hop is empty) and default
			// routes whose gateway is outside the allowlist (the
			// crawl loop will refuse them anyway, but skipping here
			// avoids audit log noise).
			if r.NextHop != "" && r.NextHop != "0.0.0.0" {
				addHint(r.NextHop, "route_next_hop")
			}
		}

		arps, err := softFail(ing.GetArpTable(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations,
			firewall.MapArp(c, arps, now)...)
		// ARP entries become low-priority hints: most are hosts not
		// gateways. The crawl loop still fingerprints them — finding
		// a switch among the hosts is exactly the point.
		for _, a := range arps {
			addHint(a.IP, "arp")
		}

		nats, err := softFail(ing.GetNatRules(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations,
			firewall.MapNatRules(c, nats, now)...)

		zones, err := softFail(ing.GetZones(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations,
			firewall.MapZones(c, zones, now)...)

		pols, err := softFail(ing.GetPolicies(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations,
			firewall.MapPolicies(c, pols, now)...)

		vpns, err := softFail(ing.GetVpnTunnels(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations,
			firewall.MapVpnTunnels(c, vpns, now)...)
		for _, v := range vpns {
			// VPN peer IPs are usually OUTSIDE the tenant allowlist
			// (they're at the branch office); the crawl's CIDR guard
			// will refuse them with an audit row. That's correct
			// behaviour — branch reachability happens via the
			// branch's own collector, not this one.
			addHint(v.PeerIP, "vpn_peer")
		}

		bgps, err := softFail(ing.GetBgpNeighbors(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations,
			firewall.MapBgpNeighbors(c, bgps, now)...)
		for _, b := range bgps {
			addHint(b.PeerIP, "bgp_peer")
		}

		ospfs, err := softFail(ing.GetOspfNeighbors(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations,
			firewall.MapOspfNeighbors(c, ospfs, now)...)
		for _, o := range ospfs {
			// OSPF "peer router ID" is often the peer's loopback IP
			// — which is reachable only via routing, but worth
			// fingerprinting because it's the canonical management
			// address on Cisco / Juniper.
			addHint(o.PeerRouterID, "ospf_peer")
		}
	}
	return res, nil
}

// softFail mirrors the dispatcher's "auth aborts, anything else gets
// logged and skipped" rule, but inside the driver. We return the empty
// slice + nil error for non-auth failures so the caller can keep going.
//
// (The dispatcher already has its own softFail for per-job errors;
// this one is for per-table inside one driver call. We keep them
// separate because the policy might diverge later — e.g., we might
// want to fail the whole job if interfaces fail but tolerate VPN-list
// failures.)
func softFail[T any](xs []T, err error) ([]T, error) {
	if err == nil {
		return xs, nil
	}
	if IsAuth(err) {
		return nil, err
	}
	// Non-auth: swallow. The dispatcher's softFail in the layer above
	// also logs it; both arms is fine — we want the message.
	return nil, nil
}
