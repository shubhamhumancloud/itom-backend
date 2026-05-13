// Package fortigate implements firewall.Ingestor against FortiOS 7.2+.
//
// Auth is a bearer token from a dedicated REST-API admin user (`config
// system api-user`) bound to a read-only accprofile and locked to the
// collector's source IP via `trusthost`. We never log in as a real admin.
//
// Multi-VDOM: every endpoint requires `?vdom=...` even on single-VDOM
// boxes. We discover the VDOM list first; the dispatcher iterates calls
// per VDOM.
//
// What we deliberately do NOT pull:
//   - the live session/conntrack table (millions of rows, runtime noise)
//   - the address book / service objects (resolved at fusion time if needed)
//   - logs (separate product surface)
package fortigate

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Ingestor implements firewall.Ingestor for FortiGate.
type Ingestor struct {
	c *httpClient
}

// New returns an unauthenticated Ingestor. Call Login to provide creds.
func New() *Ingestor {
	return &Ingestor{}
}

// Login validates creds and constructs the HTTP client. FortiGate does
// not have a separate login step — the bearer token is sent on every
// request — so we issue one cheap call to confirm the token works
// before declaring the session live.
func (f *Ingestor) Login(ctx context.Context, creds firewall.Creds) error {
	if creds.Host == "" {
		return fmt.Errorf("fortigate: host is required")
	}
	if creds.APIKey == "" {
		return fmt.Errorf("fortigate: api key is required")
	}
	c, err := newHTTPClient(creds.Host, creds.APIKey, creds.TLSFingerprintSHA256)
	if err != nil {
		return err
	}
	f.c = c

	// Cheap auth probe: pull the system status. If this fails 401 we
	// abort the whole job; if it fails 5xx the caller can retry.
	if err := f.c.get(ctx, "/api/v2/monitor/system/status", "root", nil); err != nil {
		if firewall.IsAuth(err) {
			return &firewall.AuthError{Wrapped: fmt.Errorf("fortigate: token rejected (rotate the api-user key): %w", err)}
		}
		return err
	}
	return nil
}

func (f *Ingestor) Logout() error {
	// Stateless bearer auth — nothing to revoke. Drop the client so the
	// transport pool releases connections.
	f.c = nil
	return nil
}

// ListContexts returns one Context per VDOM. The id and name are the same
// for FortiGate (vdom names go straight into the URL query).
func (f *Ingestor) ListContexts(ctx context.Context) ([]firewall.Context, error) {
	if f.c == nil {
		return nil, fmt.Errorf("fortigate: not logged in")
	}
	// /api/v2/cmdb/system/vdom uses the special "root" vdom for the
	// management plane; that VDOM always exists.
	var rows []vdomRow
	err := f.c.getPaginated(ctx, "/api/v2/cmdb/system/vdom", "root",
		func(raw json.RawMessage) error {
			var page []vdomRow
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			rows = append(rows, page...)
			return nil
		})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		// Single-VDOM box where the API user wasn't given access to
		// system/vdom. Fall back to a synthetic "root" VDOM.
		return []firewall.Context{{Name: "root", ID: "root"}}, nil
	}
	out := make([]firewall.Context, 0, len(rows))
	for _, r := range rows {
		if r.Name == "" {
			continue
		}
		out = append(out, firewall.Context{Name: r.Name, ID: r.Name})
	}
	return out, nil
}

// GetInterfaces ----------------------------------------------------------

func (f *Ingestor) GetInterfaces(ctx context.Context, c firewall.Context) ([]firewall.Interface, error) {
	var raw envelope[[]ifaceRow]
	if err := f.c.get(ctx, "/api/v2/monitor/system/interface", c.ID, &raw); err != nil {
		return nil, err
	}
	out := make([]firewall.Interface, 0, len(raw.Results))
	for _, r := range raw.Results {
		ips := make([]string, 0, len(r.IPv4Addresses))
		for _, a := range r.IPv4Addresses {
			if a.IP == "" {
				continue
			}
			ips = append(ips, cidrize(a.IP, a.Mask))
		}
		// Some FortiOS builds put the primary IP only in the flat "ip"
		// field, so we backfill from it if the array was empty.
		if len(ips) == 0 && r.IP != "" {
			parts := strings.Fields(r.IP)
			if len(parts) == 2 {
				ips = append(ips, cidrize(parts[0], parts[1]))
			}
		}
		out = append(out, firewall.Interface{
			Name:      r.Name,
			Zone:      r.Zone,
			Status:    normaliseStatus(r.Status),
			IPs:       ips,
			MAC:       r.MAC,
			VlanID:    r.Vlanid,
			IsVirtual: r.Type == "vlan" || r.Type == "tunnel" || r.Type == "loopback" || r.Type == "aggregate",
		})
	}
	return out, nil
}

// GetRoutes --------------------------------------------------------------

func (f *Ingestor) GetRoutes(ctx context.Context, c firewall.Context) ([]firewall.Route, error) {
	var raw envelope[[]routeRow]
	if err := f.c.get(ctx, "/api/v2/monitor/router/ipv4", c.ID, &raw); err != nil {
		return nil, err
	}
	out := make([]firewall.Route, 0, len(raw.Results))
	for _, r := range raw.Results {
		out = append(out, firewall.Route{
			VirtualRouter: fmt.Sprintf("vrf-%d", r.VRF),
			Prefix:        r.IPMask,
			NextHop:       r.Gateway,
			Interface:     r.Interface,
			Protocol:      r.Type,
			Distance:      r.Distance,
			Metric:        r.Metric,
		})
	}
	return out, nil
}

// GetArpTable ------------------------------------------------------------

func (f *Ingestor) GetArpTable(ctx context.Context, c firewall.Context) ([]firewall.ArpEntry, error) {
	var raw envelope[[]arpRow]
	if err := f.c.get(ctx, "/api/v2/monitor/network/arp", c.ID, &raw); err != nil {
		return nil, err
	}
	out := make([]firewall.ArpEntry, 0, len(raw.Results))
	for _, r := range raw.Results {
		out = append(out, firewall.ArpEntry{
			IP:        r.IP,
			MAC:       r.MAC,
			Interface: r.Interface,
		})
	}
	return out, nil
}

// GetNatRules ------------------------------------------------------------

// FortiGate NAT lives in two places: SNAT is a flag on
// firewall.policy; DNAT is its own firewall.vip table. We emit one
// firewall.NatRule per source and one per VIP.
func (f *Ingestor) GetNatRules(ctx context.Context, c firewall.Context) ([]firewall.NatRule, error) {
	var policies []policyRow
	err := f.c.getPaginated(ctx, "/api/v2/cmdb/firewall/policy", c.ID,
		func(raw json.RawMessage) error {
			var page []policyRow
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			policies = append(policies, page...)
			return nil
		})
	if err != nil {
		return nil, err
	}

	var vips []vipRow
	err = f.c.getPaginated(ctx, "/api/v2/cmdb/firewall/vip", c.ID,
		func(raw json.RawMessage) error {
			var page []vipRow
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			vips = append(vips, page...)
			return nil
		})
	if err != nil {
		return nil, err
	}

	out := make([]firewall.NatRule, 0, len(vips))
	for _, p := range policies {
		if p.NAT != "enable" {
			continue
		}
		out = append(out, firewall.NatRule{
			Name:          fmt.Sprintf("policy-%d-snat", p.PolicyID),
			Direction:     "src",
			OriginalSrc:   joinNames(p.SrcAddr),
			OriginalDst:   joinNames(p.DstAddr),
			Protocol:      joinNames(p.Service),
			TranslatedSrc: joinNames(p.PoolName),
		})
	}
	for _, v := range vips {
		mapped := ""
		if len(v.Mappedip) > 0 {
			mapped = v.Mappedip[0].Range
		}
		out = append(out, firewall.NatRule{
			Name:           v.Name,
			Direction:      "dst",
			OriginalDst:    v.ExtIP,
			OriginalPort:   zeroAsAny(v.ExtPort),
			Protocol:       strings.ToLower(v.Protocol),
			TranslatedDst:  mapped,
			TranslatedPort: zeroAsAny(v.MappedPort),
		})
	}
	return out, nil
}

// GetZones ---------------------------------------------------------------

func (f *Ingestor) GetZones(ctx context.Context, c firewall.Context) ([]firewall.Zone, error) {
	var rows []zoneRow
	err := f.c.getPaginated(ctx, "/api/v2/cmdb/system/zone", c.ID,
		func(raw json.RawMessage) error {
			var page []zoneRow
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			rows = append(rows, page...)
			return nil
		})
	if err != nil {
		return nil, err
	}
	out := make([]firewall.Zone, 0, len(rows))
	for _, z := range rows {
		ifs := make([]string, 0, len(z.Interface))
		for _, r := range z.Interface {
			ifs = append(ifs, r.Name)
		}
		out = append(out, firewall.Zone{Name: z.Name, Interfaces: ifs})
	}
	return out, nil
}

// GetPolicies ------------------------------------------------------------

func (f *Ingestor) GetPolicies(ctx context.Context, c firewall.Context) ([]firewall.Policy, error) {
	var rows []policyRow
	err := f.c.getPaginated(ctx, "/api/v2/cmdb/firewall/policy", c.ID,
		func(raw json.RawMessage) error {
			var page []policyRow
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			rows = append(rows, page...)
			return nil
		})
	if err != nil {
		return nil, err
	}
	out := make([]firewall.Policy, 0, len(rows))
	for _, p := range rows {
		name := p.Name
		if name == "" {
			name = fmt.Sprintf("policy-%d", p.PolicyID)
		}
		out = append(out, firewall.Policy{
			Name:         name,
			FromZone:     joinNames(p.SrcIntf),
			ToZone:       joinNames(p.DstIntf),
			Sources:      namesOf(p.SrcAddr),
			Destinations: namesOf(p.DstAddr),
			Services:     namesOf(p.Service),
			Action:       p.Action,
			Enabled:      p.Status == "enable",
		})
	}
	return out, nil
}

// GetVpnTunnels ----------------------------------------------------------

// Merge phase1 (peer gateway + IKE version) with phase2 (proxy IDs ==
// the local/remote subnet binding) and the live monitor (status).
func (f *Ingestor) GetVpnTunnels(ctx context.Context, c firewall.Context) ([]firewall.VpnTunnel, error) {
	var phase1s []phase1Row
	err := f.c.getPaginated(ctx, "/api/v2/cmdb/vpn.ipsec/phase1-interface", c.ID,
		func(raw json.RawMessage) error {
			var page []phase1Row
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			phase1s = append(phase1s, page...)
			return nil
		})
	if err != nil {
		return nil, err
	}

	var phase2s []phase2Row
	err = f.c.getPaginated(ctx, "/api/v2/cmdb/vpn.ipsec/phase2-interface", c.ID,
		func(raw json.RawMessage) error {
			var page []phase2Row
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			phase2s = append(phase2s, page...)
			return nil
		})
	if err != nil {
		return nil, err
	}

	var mon envelope[[]ipsecMonitorRow]
	if err := f.c.get(ctx, "/api/v2/monitor/vpn/ipsec", c.ID, &mon); err != nil {
		// Tunnels-down at lab time isn't fatal — we still want the config.
		mon.Results = nil
	}

	statusByName := map[string]string{}
	for _, m := range mon.Results {
		key := m.Phase1Name
		if key == "" {
			key = m.Name
		}
		statusByName[key] = m.Status
	}

	// Group phase2s by phase1name.
	p2ByPhase1 := map[string][]phase2Row{}
	for _, p := range phase2s {
		p2ByPhase1[p.Phase1Name] = append(p2ByPhase1[p.Phase1Name], p)
	}

	out := make([]firewall.VpnTunnel, 0, len(phase1s))
	for _, p := range phase1s {
		locals := []string{}
		remotes := []string{}
		for _, q := range p2ByPhase1[p.Name] {
			if c := cidrFromFortiMask(q.SrcSubnet); c != "" {
				locals = append(locals, c)
			}
			if c := cidrFromFortiMask(q.DstSubnet); c != "" {
				remotes = append(remotes, c)
			}
		}
		out = append(out, firewall.VpnTunnel{
			Name:          p.Name,
			PeerIP:        p.RemoteGW,
			LocalSubnets:  locals,
			RemoteSubnets: remotes,
			Status:        firstNonEmpty(statusByName[p.Name], "unknown"),
			IKEVersion:    p.IKEVersion,
		})
	}
	return out, nil
}

// GetBgpNeighbors --------------------------------------------------------

func (f *Ingestor) GetBgpNeighbors(ctx context.Context, c firewall.Context) ([]firewall.BgpNeighbor, error) {
	var raw envelope[[]bgpRow]
	if err := f.c.get(ctx, "/api/v2/monitor/router/bgp/neighbors", c.ID, &raw); err != nil {
		// BGP not configured → FortiOS returns 4xx; treat as empty.
		return nil, nil
	}
	out := make([]firewall.BgpNeighbor, 0, len(raw.Results))
	for _, r := range raw.Results {
		out = append(out, firewall.BgpNeighbor{
			PeerIP:    r.NeighborIP,
			PeerAS:    r.RemoteAS,
			LocalAS:   r.LocalAS,
			State:     r.State,
			UptimeSec: r.UptimeSec,
		})
	}
	return out, nil
}

// GetOspfNeighbors -------------------------------------------------------

func (f *Ingestor) GetOspfNeighbors(ctx context.Context, c firewall.Context) ([]firewall.OspfNeighbor, error) {
	var raw envelope[[]ospfRow]
	if err := f.c.get(ctx, "/api/v2/monitor/router/ospf/neighbors", c.ID, &raw); err != nil {
		return nil, nil
	}
	out := make([]firewall.OspfNeighbor, 0, len(raw.Results))
	for _, r := range raw.Results {
		out = append(out, firewall.OspfNeighbor{
			PeerRouterID: firstNonEmpty(r.NeighborID, r.IP),
			Area:         r.Area,
			State:        r.State,
			Interface:    r.Interface,
		})
	}
	return out, nil
}

// ---------- helpers ----------

func cidrize(ip, mask string) string {
	if ip == "" {
		return ""
	}
	if strings.Contains(mask, ".") {
		// dotted-quad mask -> count the ones.
		m := net.IPMask(net.ParseIP(mask).To4())
		if m != nil {
			ones, _ := m.Size()
			return fmt.Sprintf("%s/%d", ip, ones)
		}
	}
	if strings.HasPrefix(mask, "/") {
		return ip + mask
	}
	if mask == "" {
		return ip
	}
	return fmt.Sprintf("%s/%s", ip, mask)
}

// cidrFromFortiMask turns "10.0.0.0 255.255.0.0" into "10.0.0.0/16".
func cidrFromFortiMask(s string) string {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return cidrize(parts[0], parts[1])
}

func normaliseStatus(s string) string {
	switch strings.ToLower(s) {
	case "up", "enable":
		return "up"
	case "down", "disable":
		return "down"
	default:
		return "unknown"
	}
}

func joinNames(refs []namedRef) string {
	if len(refs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.Name != "" {
			parts = append(parts, r.Name)
		}
	}
	return strings.Join(parts, ",")
}

func namesOf(refs []namedRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.Name != "" {
			out = append(out, r.Name)
		}
	}
	return out
}

func zeroAsAny(s string) string {
	if s == "" || s == "0" || s == "0-65535" {
		return "any"
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
