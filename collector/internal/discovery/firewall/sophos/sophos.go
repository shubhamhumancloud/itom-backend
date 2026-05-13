// Package sophos implements firewall.Ingestor against Sophos Firewall
// (formerly XG Firewall) running SFOS 18.x+ and the XGS/XG appliance
// line. The XGS series, the virtual SF appliances, and the rebranded
// "Sophos Firewall" SaaS Manager all expose the same XML API surface.
//
// API URL: https://<fw>:4444/webconsole/APIController
//
// Auth model is unusual: there is NO session token. Every request body
// must include a `<Login>` block with the username and password. The
// only protections are HTTPS, the API-admin role, and the source-IP
// allowlist configured in System → Administration → Device Access.
//
// Request format (form-encoded POST):
//
//   reqxml=<Request>
//            <Login>
//              <Username>...</Username>
//              <Password>...</Password>
//            </Login>
//            <Get>
//              <Interface></Interface>
//            </Get>
//          </Request>
//
// Response status is signalled by `<Login><status>Authentication
// Successful</status></Login>` — a plain HTTP 200 with the failure
// message in the body is the documented error path, which is why this
// driver inspects the parsed body before declaring success.
//
// What we DO pull:
//   - Interface, Zone, FirewallRule, NATRule
//   - VPNIPSecConnection (peer IP + subnets)
//   - BGPNeighbor, OSPFNeighbor (when dynamic routing is enabled)
//   - UnicastRoute (static routes)
//
// What we currently SKIP (XML API doesn't expose these reliably across
// versions; tracked as future polish):
//   - Live ARP cache
//   - Live IPv4 routing table
package sophos

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Default management port for the Sophos XML API. Operators can change
// this; if creds.Host carries an explicit port we honour it instead.
const defaultPort = 4444

// Ingestor implements firewall.Ingestor for Sophos Firewall.
type Ingestor struct {
	base     string
	username string
	password string
	httpc    *http.Client
}

// New returns an unauthenticated Ingestor.
func New() *Ingestor { return &Ingestor{} }

// Login stashes the username/password (Sophos sends them on every
// request) and runs a cheap probe to confirm they work.
func (s *Ingestor) Login(ctx context.Context, creds firewall.Creds) error {
	if creds.Host == "" {
		return fmt.Errorf("sophos: host is required")
	}
	if creds.Username == "" || creds.Password == "" {
		// Sophos doesn't support API-key auth — only Username+Password
		// of an API-role admin. If the operator stored the password in
		// the APIKey field (older credential rows) accept it there.
		if creds.APIKey != "" && creds.Username != "" {
			creds.Password = creds.APIKey
		} else {
			return fmt.Errorf("sophos: username + password required")
		}
	}

	host := strings.TrimRight(creds.Host, "/")
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	// Sophos serves the API on port 4444 by default. Don't override an
	// explicit port the operator already set.
	if !hasExplicitPort(host) {
		host = fmt.Sprintf("%s:%d", host, defaultPort)
	}
	s.base = host
	s.username = creds.Username
	s.password = creds.Password

	tr := &http.Transport{
		// Sophos appliances ship self-signed certs. Per-tenant pinning
		// is the right answer; until that helper is lifted into the
		// firewall package we fall back to skip-verify when no pin is
		// supplied.
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: creds.TLSFingerprintSHA256 == ""},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
	}
	s.httpc = &http.Client{Transport: tr, Timeout: 60 * time.Second}

	// Auth probe: `Get Interface` is universally available and cheap.
	var probe interfaceResp
	if err := s.fetch(ctx, "<Get><Interface></Interface></Get>", &probe); err != nil {
		return err
	}
	return nil
}

func (s *Ingestor) Logout() error {
	// No session to revoke (creds are sent per-request). Drop the
	// client to release transport connections + zero stored secrets.
	s.username = ""
	s.password = ""
	s.httpc = nil
	return nil
}

// ListContexts — Sophos doesn't have a multi-context concept. Return
// one synthetic "system" context so the outer loop still iterates once.
func (s *Ingestor) ListContexts(ctx context.Context) ([]firewall.Context, error) {
	return []firewall.Context{{Name: "system", ID: "system"}}, nil
}

// GetInterfaces ----------------------------------------------------------

func (s *Ingestor) GetInterfaces(ctx context.Context, c firewall.Context) ([]firewall.Interface, error) {
	var resp interfaceResp
	if err := s.fetch(ctx, "<Get><Interface></Interface></Get>", &resp); err != nil {
		return nil, err
	}
	out := make([]firewall.Interface, 0, len(resp.Interfaces))
	for _, i := range resp.Interfaces {
		ips := []string{}
		if i.IPAddress != "" {
			ips = append(ips, cidrFromNetmask(i.IPAddress, i.Netmask))
		}
		out = append(out, firewall.Interface{
			Name:      defaultName(i.Name, i.HardwareName),
			Zone:      i.Zone,
			Status:    normaliseStatus(i.Status),
			IPs:       ips,
			MAC:       i.MACAddress,
			IsVirtual: i.InterfaceType == "VLAN" || i.InterfaceType == "Tunnel" || i.InterfaceType == "Bridge",
		})
	}
	return out, nil
}

// GetRoutes — Sophos `<UnicastRoute>` is the static-route table. Live
// (dynamic) routes can be pulled via per-protocol queries — we cover
// them in GetBgpNeighbors / GetOspfNeighbors as adjacencies, which is
// what the fusion layer needs.
func (s *Ingestor) GetRoutes(ctx context.Context, c firewall.Context) ([]firewall.Route, error) {
	var resp unicastRouteResp
	if err := s.fetch(ctx, "<Get><UnicastRoute></UnicastRoute></Get>", &resp); err != nil {
		return nil, nil // many estates manage routes via dynamic protocols only
	}
	out := make([]firewall.Route, 0, len(resp.Routes))
	for _, r := range resp.Routes {
		out = append(out, firewall.Route{
			VirtualRouter: "default",
			Prefix:        cidrFromNetmask(r.DstNetwork, r.DstNetmask),
			NextHop:       r.Gateway,
			Interface:     r.Interface,
			Protocol:      "static",
			Distance:      r.Distance,
		})
	}
	return out, nil
}

// GetArpTable — XML API does not reliably expose the live ARP cache
// across Sophos versions. Returning empty is honest.
func (s *Ingestor) GetArpTable(ctx context.Context, c firewall.Context) ([]firewall.ArpEntry, error) {
	return nil, nil
}

// GetNatRules — combined SNAT + DNAT rulebase.
func (s *Ingestor) GetNatRules(ctx context.Context, c firewall.Context) ([]firewall.NatRule, error) {
	var resp natRuleResp
	if err := s.fetch(ctx, "<Get><NATRule></NATRule></Get>", &resp); err != nil {
		return nil, err
	}
	out := make([]firewall.NatRule, 0, len(resp.NATRules))
	for _, r := range resp.NATRules {
		dir := "src"
		if r.DestinationTranslation != "" && r.DestinationTranslation != "Original" {
			dir = "dst"
		}
		out = append(out, firewall.NatRule{
			Name:           r.Name,
			Direction:      dir,
			OriginalSrc:    joinSophos(r.OriginalSource),
			OriginalDst:    joinSophos(r.OriginalDestination),
			Protocol:       joinSophos(r.OriginalService),
			TranslatedSrc:  r.SourceTranslation,
			TranslatedDst:  r.DestinationTranslation,
			TranslatedPort: r.ServiceTranslation,
		})
	}
	return out, nil
}

// GetZones — Sophos zones (LAN/WAN/DMZ/VPN/WiFi + custom).
func (s *Ingestor) GetZones(ctx context.Context, c firewall.Context) ([]firewall.Zone, error) {
	var resp zoneResp
	if err := s.fetch(ctx, "<Get><Zone></Zone></Get>", &resp); err != nil {
		return nil, err
	}
	out := make([]firewall.Zone, 0, len(resp.Zones))
	for _, z := range resp.Zones {
		out = append(out, firewall.Zone{
			Name:       z.Name,
			Interfaces: z.Members,
		})
	}
	return out, nil
}

// GetPolicies — security rulebase. Sophos "FirewallRule" is the closest
// analogue to a policy entry: zones, source/dest groups, services, action.
func (s *Ingestor) GetPolicies(ctx context.Context, c firewall.Context) ([]firewall.Policy, error) {
	var resp firewallRuleResp
	if err := s.fetch(ctx, "<Get><FirewallRule></FirewallRule></Get>", &resp); err != nil {
		return nil, err
	}
	out := make([]firewall.Policy, 0, len(resp.Rules))
	for _, r := range resp.Rules {
		out = append(out, firewall.Policy{
			Name:         r.Name,
			FromZone:     joinSophos(r.NetworkPolicy.SourceZones),
			ToZone:       joinSophos(r.NetworkPolicy.DestinationZones),
			Sources:      r.NetworkPolicy.SourceNetworks,
			Destinations: r.NetworkPolicy.DestinationNetworks,
			Services:     r.NetworkPolicy.Services,
			Action:       strings.ToLower(r.NetworkPolicy.Action),
			Enabled:      r.Status != "Disable" && r.Status != "Disabled",
		})
	}
	return out, nil
}

// GetVpnTunnels — IPsec site-to-site connections.
func (s *Ingestor) GetVpnTunnels(ctx context.Context, c firewall.Context) ([]firewall.VpnTunnel, error) {
	var resp ipsecResp
	if err := s.fetch(ctx, "<Get><VPNIPSecConnection></VPNIPSecConnection></Get>", &resp); err != nil {
		return nil, err
	}
	out := make([]firewall.VpnTunnel, 0, len(resp.Connections))
	for _, v := range resp.Connections {
		out = append(out, firewall.VpnTunnel{
			Name:          v.Name,
			PeerIP:        v.RemoteGateway,
			LocalSubnets:  v.LocalSubnets,
			RemoteSubnets: v.RemoteSubnets,
			Status:        normaliseStatus(v.ConnectionStatus),
			IKEVersion:    v.IKEVersion,
		})
	}
	return out, nil
}

// GetBgpNeighbors --------------------------------------------------------

func (s *Ingestor) GetBgpNeighbors(ctx context.Context, c firewall.Context) ([]firewall.BgpNeighbor, error) {
	var resp bgpNeighborResp
	if err := s.fetch(ctx, "<Get><BGPNeighbor></BGPNeighbor></Get>", &resp); err != nil {
		return nil, nil // BGP is opt-in
	}
	out := make([]firewall.BgpNeighbor, 0, len(resp.Neighbors))
	for _, b := range resp.Neighbors {
		out = append(out, firewall.BgpNeighbor{
			PeerIP:  b.IPAddress,
			PeerAS:  b.RemoteAS,
			LocalAS: b.LocalAS,
			State:   strings.ToLower(b.Status),
		})
	}
	return out, nil
}

// GetOspfNeighbors -------------------------------------------------------

func (s *Ingestor) GetOspfNeighbors(ctx context.Context, c firewall.Context) ([]firewall.OspfNeighbor, error) {
	var resp ospfNeighborResp
	if err := s.fetch(ctx, "<Get><OSPFNeighbor></OSPFNeighbor></Get>", &resp); err != nil {
		return nil, nil
	}
	out := make([]firewall.OspfNeighbor, 0, len(resp.Neighbors))
	for _, o := range resp.Neighbors {
		out = append(out, firewall.OspfNeighbor{
			PeerRouterID: o.RouterID,
			Area:         o.Area,
			State:        strings.ToLower(o.State),
			Interface:    o.Interface,
		})
	}
	return out, nil
}

// ----- internal helpers -----

// fetch issues one XML API request and decodes the response into dst.
// The Sophos API uses a single POST endpoint with the request XML in
// the `reqxml` form parameter; the response is XML.
//
// Auth-failure detection happens AFTER parsing: a 200 response with
// `<Login><status>Authentication Failure</status></Login>` is the
// documented error path for a rejected credential.
func (s *Ingestor) fetch(ctx context.Context, body string, dst any) error {
	// Wrap the supplied <Get>...</Get> fragment inside a full Request
	// envelope with the per-call Login block.
	reqXML := fmt.Sprintf(
		`<Request>%s%s</Request>`,
		fmt.Sprintf(`<Login><Username>%s</Username><Password>%s</Password></Login>`,
			xmlEscape(s.username), xmlEscape(s.password)),
		body,
	)

	form := url.Values{}
	form.Set("reqxml", reqXML)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		s.base+"/webconsole/APIController", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/xml")

	resp, err := s.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("sophos POST APIController: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &firewall.AuthError{Wrapped: fmt.Errorf("sophos HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))}
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("sophos HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}

	// Inspect the Login status before decoding the rest. The response
	// envelope is shared across every call type.
	var env responseEnvelope
	if err := xml.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("sophos decode envelope: %w", err)
	}
	switch strings.TrimSpace(strings.ToLower(env.Login.Status)) {
	case "authentication successful", "":
		// Empty status occurs on some firmware versions when the call
		// is purely a Get without a separate Login probe — accept it.
	case "authentication failure", "incorrect username or password":
		return &firewall.AuthError{Wrapped: fmt.Errorf("sophos: %s", env.Login.Status)}
	default:
		// Pass through — Sophos uses lots of bespoke phrases ("API
		// configuration is disabled", "Source IP not allowed") that
		// aren't auth failures per se but should bail the whole job.
		return fmt.Errorf("sophos login status: %s", env.Login.Status)
	}

	if dst == nil {
		return nil
	}
	if err := xml.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("sophos decode body: %w", err)
	}
	return nil
}

func hasExplicitPort(host string) bool {
	// Strip scheme to do the lookup.
	stripped := strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	// IPv6 literals are in brackets — `[::1]:4444`
	if strings.HasPrefix(stripped, "[") {
		return strings.Contains(stripped, "]:")
	}
	// Last colon must come after the last slash (path may have :) and
	// must precede only digits.
	if i := strings.LastIndex(stripped, ":"); i > -1 {
		port := stripped[i+1:]
		if slash := strings.Index(port, "/"); slash >= 0 {
			port = port[:slash]
		}
		if port == "" {
			return false
		}
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func defaultName(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func joinSophos(xs []string) string {
	clean := make([]string, 0, len(xs))
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			clean = append(clean, x)
		}
	}
	return strings.Join(clean, ",")
}

func normaliseStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "connected", "up", "active", "active-active", "established":
		return "up"
	case "disconnected", "down", "inactive", "not-established":
		return "down"
	}
	return "unknown"
}

// cidrFromNetmask — same dotted-mask → CIDR conversion the ASA driver
// uses. Kept local to avoid a cross-package helper for one small fn.
func cidrFromNetmask(ip, mask string) string {
	if ip == "" {
		return ""
	}
	if mask == "" {
		return ip
	}
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return ip + " " + mask
	}
	n := 0
	for _, p := range parts {
		v := 0
		fmt.Sscanf(p, "%d", &v)
		switch v {
		case 255:
			n += 8
		case 254:
			n += 7
		case 252:
			n += 6
		case 248:
			n += 5
		case 240:
			n += 4
		case 224:
			n += 3
		case 192:
			n += 2
		case 128:
			n += 1
		case 0:
		default:
			return ip + " " + mask
		}
	}
	return fmt.Sprintf("%s/%d", ip, n)
}
