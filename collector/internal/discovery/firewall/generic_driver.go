package firewall

import (
	"context"
	"errors"
	"time"

	"github.com/itom-mini/collector/internal/discovery/device"
)

// GenericDriver adapts any firewall.Ingestor to the device.Driver
// contract. Every supported firewall vendor uses this — each vendor
// implementation only needs to satisfy firewall.Ingestor; the
// observation mapping + neighbour hint harvesting + chassis identity
// extraction lives here once.
//
// Per-vendor driver.go files reduce to a one-liner Factory that
// wires this struct.
type GenericDriver struct {
	vendor  device.Vendor
	build   func() Ingestor
	chassis func(Ingestor) string // optional — return "" to fall back to host IP
}

// NewGenericDriver returns a device.Driver that delegates to the
// firewall.Ingestor produced by `build`. `chassis` is an optional hook
// for drivers that can cheaply extract a chassis serial post-Login;
// pass nil to leave ChassisID empty (the crawler then dedups by IP).
func NewGenericDriver(
	v device.Vendor,
	build func() Ingestor,
	chassis func(Ingestor) string,
) device.Driver {
	return &GenericDriver{vendor: v, build: build, chassis: chassis}
}

func (d *GenericDriver) Vendor() device.Vendor { return d.vendor }

// Ingest pulls every supported table from the firewall and emits both
// observations and crawl-hint neighbours. The fixed call order matches
// the firewall.Ingestor docstring: Login → ListContexts → Get* per
// context → Logout.
//
// Per-table errors that are NOT auth failures are swallowed: a
// firewall may legitimately lack BGP/OSPF/IPsec without that being a
// reason to fail the whole job. Auth failure aborts the call.
func (d *GenericDriver) Ingest(ctx context.Context, creds device.Creds) (device.IngestResult, error) {
	fcreds := Creds{
		Host:                 creds.Host,
		Username:             creds.Username,
		Password:             creds.Password,
		APIKey:               creds.APIKey,
		TLSFingerprintSHA256: creds.TLSFingerprintSHA256,
	}
	ing := d.build()
	if err := ing.Login(ctx, fcreds); err != nil {
		return device.IngestResult{}, err
	}
	defer func() { _ = ing.Logout() }()

	contexts, err := ing.ListContexts(ctx)
	if err != nil {
		return device.IngestResult{}, err
	}

	res := device.IngestResult{}
	if d.chassis != nil {
		res.ChassisID = d.chassis(ing)
	}

	seenNeighbour := map[string]bool{}
	addHint := func(ip, reason string) {
		if ip == "" || ip == "0.0.0.0" || ip == "::" {
			return
		}
		key := ip + "|" + reason
		if seenNeighbour[key] {
			return
		}
		seenNeighbour[key] = true
		res.Neighbours = append(res.Neighbours, device.NeighbourHint{IP: ip, Reason: reason})
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
		res.Observations = append(res.Observations, MapInterfaces(c, ifaces, now)...)

		routes, err := softFail(ing.GetRoutes(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations, MapRoutes(c, routes, now)...)
		for _, r := range routes {
			if r.NextHop != "" && r.NextHop != "0.0.0.0" {
				addHint(r.NextHop, "route_next_hop")
			}
		}

		arps, err := softFail(ing.GetArpTable(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations, MapArp(c, arps, now)...)
		for _, a := range arps {
			addHint(a.IP, "arp")
		}

		nats, err := softFail(ing.GetNatRules(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations, MapNatRules(c, nats, now)...)

		zones, err := softFail(ing.GetZones(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations, MapZones(c, zones, now)...)

		pols, err := softFail(ing.GetPolicies(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations, MapPolicies(c, pols, now)...)

		vpns, err := softFail(ing.GetVpnTunnels(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations, MapVpnTunnels(c, vpns, now)...)
		for _, v := range vpns {
			addHint(v.PeerIP, "vpn_peer")
		}

		bgps, err := softFail(ing.GetBgpNeighbors(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations, MapBgpNeighbors(c, bgps, now)...)
		for _, b := range bgps {
			addHint(b.PeerIP, "bgp_peer")
		}

		ospfs, err := softFail(ing.GetOspfNeighbors(ctx, c))
		if err != nil {
			return res, err
		}
		res.Observations = append(res.Observations, MapOspfNeighbors(c, ospfs, now)...)
		for _, o := range ospfs {
			addHint(o.PeerRouterID, "ospf_peer")
		}
	}
	return res, nil
}

// AuthError is the contract every vendor implementation must expose:
// a sentinel (or wrapped) error that satisfies errors.Is(err, AuthError).
// This is the only signal the dispatcher uses to abort vs. continue.
type AuthError struct{ Wrapped error }

func (e *AuthError) Error() string {
	if e.Wrapped == nil {
		return "firewall: authentication failed"
	}
	return "firewall: authentication failed: " + e.Wrapped.Error()
}
func (e *AuthError) Unwrap() error { return e.Wrapped }

// IsAuth reports whether `err` represents an auth failure from any
// vendor driver. Drivers are expected to wrap their own auth errors
// with *AuthError so this single check serves all of them.
func IsAuth(err error) bool {
	if err == nil {
		return false
	}
	var ae *AuthError
	return errors.As(err, &ae)
}

// softFail mirrors the dispatcher's "auth aborts, anything else gets
// logged and skipped" rule. Non-auth failures yield (nil, nil) so the
// outer loop continues with the next table.
func softFail[T any](xs []T, err error) ([]T, error) {
	if err == nil {
		return xs, nil
	}
	if IsAuth(err) {
		return nil, err
	}
	return nil, nil
}
