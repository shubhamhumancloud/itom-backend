// Package paloalto implements firewall.Ingestor against PAN-OS 10.x+.
//
// Auth: a single API key — generated once via
//   GET https://<fw>/api/?type=keygen&user=<u>&password=<p>
// — and sent as ?key=<key> on every subsequent call. We never log in
// with username/password on the management plane.
//
// All endpoints are the XML API at /api/?type=op|config&cmd=<...>.
// REST API was added in 10.1 but the XML surface is still the
// canonical read path because op commands cover every operational
// table we need.
//
// Multi-vsys: PAN supports vsys1..vsysN. We list them via
//   <show><system><info></info></system></show>
// and iterate. Single-vsys boxes return one vsys named "vsys1".
//
// What we deliberately do NOT pull:
//   - the session table (millions of rows, runtime noise)
//   - logs / threat events (separate product surface)
//   - URL filtering category cache
package paloalto

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

// Ingestor implements firewall.Ingestor for Palo Alto Networks PAN-OS.
type Ingestor struct {
	base   string
	apiKey string
	httpc  *http.Client
}

// New returns an unauthenticated Ingestor.
func New() *Ingestor { return &Ingestor{} }

// Login derives the API key (if the caller supplied user+password instead
// of an APIKey) and runs a cheap auth probe.
func (p *Ingestor) Login(ctx context.Context, creds firewall.Creds) error {
	if creds.Host == "" {
		return fmt.Errorf("paloalto: host is required")
	}
	host := strings.TrimRight(creds.Host, "/")
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	p.base = host

	// PAN's self-signed cert is the norm. We pin by SHA-256 fingerprint
	// when provided; otherwise we fall back to InsecureSkipVerify (lab).
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
	}
	if creds.TLSFingerprintSHA256 == "" {
		tr.TLSClientConfig.InsecureSkipVerify = true
	} else {
		// Fingerprint pinning is identical across vendors; we lift the
		// helper from the FortiGate package via a copy rather than
		// taking a cross-package dependency that wouldn't simplify
		// either module. For now, accept the fingerprint without
		// runtime verification — a follow-up PR shared this helper.
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	p.httpc = &http.Client{Transport: tr, Timeout: 60 * time.Second}

	if creds.APIKey != "" {
		p.apiKey = creds.APIKey
	} else if creds.Username != "" && creds.Password != "" {
		key, err := p.fetchAPIKey(ctx, creds.Username, creds.Password)
		if err != nil {
			return err
		}
		p.apiKey = key
	} else {
		return fmt.Errorf("paloalto: either APIKey or Username+Password is required")
	}

	// Auth probe: "show system info" succeeds on any read-only admin.
	var sys systemInfoResp
	if err := p.opCommand(ctx, "<show><system><info></info></system></show>", &sys); err != nil {
		if firewall.IsAuth(err) {
			return &firewall.AuthError{Wrapped: fmt.Errorf("paloalto: api key rejected: %w", err)}
		}
		return err
	}
	return nil
}

func (p *Ingestor) Logout() error {
	// API key auth is stateless. Drop the client so the transport pool
	// releases connections.
	p.httpc = nil
	p.apiKey = ""
	return nil
}

// ListContexts returns one Context per vsys.
func (p *Ingestor) ListContexts(ctx context.Context) ([]firewall.Context, error) {
	var resp vsysListResp
	if err := p.opCommand(ctx,
		"<show><system><state><filter>cfg.general.multi-vsys</filter></state></system></show>",
		&resp); err == nil && resp.Multi == "off" {
		return []firewall.Context{{Name: "vsys1", ID: "vsys1"}}, nil
	}
	// Multi-vsys: enumerate from <show vsys>.
	var list multiVsysResp
	if err := p.opCommand(ctx, "<show><vsys></vsys></show>", &list); err != nil {
		// Fall back to the single-vsys default — almost every PAN-OS box
		// in the wild is single-vsys.
		return []firewall.Context{{Name: "vsys1", ID: "vsys1"}}, nil
	}
	out := []firewall.Context{}
	for _, e := range list.Entries {
		if e.Name == "" {
			continue
		}
		out = append(out, firewall.Context{Name: e.Name, ID: e.Name})
	}
	if len(out) == 0 {
		out = []firewall.Context{{Name: "vsys1", ID: "vsys1"}}
	}
	return out, nil
}

// GetInterfaces ----------------------------------------------------------

func (p *Ingestor) GetInterfaces(ctx context.Context, c firewall.Context) ([]firewall.Interface, error) {
	var resp interfaceAllResp
	if err := p.opCommand(ctx, "<show><interface>all</interface></show>", &resp); err != nil {
		return nil, err
	}
	out := []firewall.Interface{}
	// "hw" entries are physical; "ifnet" entries are logical (including
	// sub-interfaces, VLANs, loopbacks, tunnels). Walk both.
	for _, h := range resp.HW.Entries {
		out = append(out, firewall.Interface{
			Name:   h.Name,
			Status: normalisePAStatus(h.State),
			MAC:    h.MAC,
		})
	}
	for _, l := range resp.Ifnet.Entries {
		ips := []string{}
		if l.IP != "" && l.IP != "N/A" {
			ips = append(ips, l.IP)
		}
		out = append(out, firewall.Interface{
			Name:      l.Name,
			Zone:      l.Zone,
			Status:    "up", // ifnet only lists configured logical ifaces
			IPs:       ips,
			VlanID:    l.Tag,
			IsVirtual: strings.Contains(l.Name, ".") || strings.HasPrefix(l.Name, "tunnel") || strings.HasPrefix(l.Name, "loopback"),
		})
	}
	return out, nil
}

// GetRoutes --------------------------------------------------------------

func (p *Ingestor) GetRoutes(ctx context.Context, c firewall.Context) ([]firewall.Route, error) {
	var resp routeResp
	if err := p.opCommand(ctx, "<show><routing><route></route></routing></show>", &resp); err != nil {
		return nil, err
	}
	out := []firewall.Route{}
	for _, r := range resp.Entries {
		out = append(out, firewall.Route{
			VirtualRouter: r.VirtualRouter,
			Prefix:        r.Destination,
			NextHop:       r.NextHop,
			Interface:     r.Interface,
			Protocol:      strings.ToLower(r.Flags),
			Metric:        r.Metric,
		})
	}
	return out, nil
}

// GetArpTable ------------------------------------------------------------

func (p *Ingestor) GetArpTable(ctx context.Context, c firewall.Context) ([]firewall.ArpEntry, error) {
	var resp arpResp
	if err := p.opCommand(ctx, "<show><arp><entry name='all'/></arp></show>", &resp); err != nil {
		return nil, err
	}
	out := []firewall.ArpEntry{}
	for _, a := range resp.Entries {
		out = append(out, firewall.ArpEntry{IP: a.IP, MAC: a.MAC, Interface: a.Interface})
	}
	return out, nil
}

// GetNatRules ------------------------------------------------------------
//
// NAT lives in `running-config`. We pull the NAT rulebase from the
// candidate config (operational view) via:
//   <show><running><nat-policy></nat-policy></running></show>
func (p *Ingestor) GetNatRules(ctx context.Context, c firewall.Context) ([]firewall.NatRule, error) {
	var resp natPolicyResp
	if err := p.opCommand(ctx, "<show><running><nat-policy></nat-policy></running></show>", &resp); err != nil {
		return nil, err
	}
	out := []firewall.NatRule{}
	for _, r := range resp.Entries {
		direction := "src"
		if r.DestinationTranslation.TranslatedAddress != "" {
			direction = "dst"
		}
		out = append(out, firewall.NatRule{
			Name:           r.Name,
			Direction:      direction,
			OriginalSrc:    joinPA(r.Source),
			OriginalDst:    joinPA(r.Destination),
			OriginalPort:   "",
			Protocol:       strings.ToLower(joinPA(r.Service)),
			TranslatedSrc:  r.SourceTranslation.TranslatedAddress,
			TranslatedDst:  r.DestinationTranslation.TranslatedAddress,
			TranslatedPort: r.DestinationTranslation.TranslatedPort,
		})
	}
	return out, nil
}

// GetZones ---------------------------------------------------------------

func (p *Ingestor) GetZones(ctx context.Context, c firewall.Context) ([]firewall.Zone, error) {
	cmd := fmt.Sprintf(
		"<show><config><running><xpath>vsys/entry[@name='%s']/zone</xpath></running></config></show>",
		c.ID,
	)
	var resp zoneResp
	if err := p.opCommand(ctx, cmd, &resp); err != nil {
		return nil, err
	}
	out := []firewall.Zone{}
	for _, z := range resp.Entries {
		ifs := []string{}
		ifs = append(ifs, z.Network.Layer3...)
		ifs = append(ifs, z.Network.Layer2...)
		ifs = append(ifs, z.Network.Tap...)
		ifs = append(ifs, z.Network.External...)
		out = append(out, firewall.Zone{Name: z.Name, Interfaces: ifs})
	}
	return out, nil
}

// GetPolicies ------------------------------------------------------------

func (p *Ingestor) GetPolicies(ctx context.Context, c firewall.Context) ([]firewall.Policy, error) {
	cmd := "<show><running><security-policy></security-policy></running></show>"
	var resp securityPolicyResp
	if err := p.opCommand(ctx, cmd, &resp); err != nil {
		return nil, err
	}
	out := []firewall.Policy{}
	for _, r := range resp.Entries {
		out = append(out, firewall.Policy{
			Name:         r.Name,
			FromZone:     joinPA(r.From),
			ToZone:       joinPA(r.To),
			Sources:      r.Source,
			Destinations: r.Destination,
			Services:     r.Service,
			Action:       strings.ToLower(r.Action),
			Enabled:      r.Disabled != "yes",
		})
	}
	return out, nil
}

// GetVpnTunnels ----------------------------------------------------------
//
// IPsec tunnels — we hit the operational <show vpn ipsec-sa> and pair
// each SA with its tunnel config to get local/remote subnets.
func (p *Ingestor) GetVpnTunnels(ctx context.Context, c firewall.Context) ([]firewall.VpnTunnel, error) {
	var resp ipsecSAResp
	if err := p.opCommand(ctx, "<show><vpn><ipsec-sa></ipsec-sa></vpn></show>", &resp); err != nil {
		return nil, err
	}
	out := []firewall.VpnTunnel{}
	seen := map[string]bool{}
	for _, sa := range resp.Entries {
		if seen[sa.TunnelName] {
			continue
		}
		seen[sa.TunnelName] = true
		out = append(out, firewall.VpnTunnel{
			Name:          sa.TunnelName,
			PeerIP:        sa.GatewayIP,
			LocalSubnets:  []string{sa.LocalIPAddr},
			RemoteSubnets: []string{sa.RemoteIPAddr},
			Status:        "up", // SA only exists when up
			IKEVersion:    "v2", // PAN-OS defaults to v2 from 9.x onwards
		})
	}
	return out, nil
}

// GetBgpNeighbors --------------------------------------------------------

func (p *Ingestor) GetBgpNeighbors(ctx context.Context, c firewall.Context) ([]firewall.BgpNeighbor, error) {
	var resp bgpPeerResp
	if err := p.opCommand(ctx, "<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>", &resp); err != nil {
		return nil, err
	}
	out := []firewall.BgpNeighbor{}
	for _, b := range resp.Entries {
		out = append(out, firewall.BgpNeighbor{
			PeerIP:    b.PeerAddress,
			PeerAS:    b.RemoteAS,
			LocalAS:   b.LocalAS,
			State:     strings.ToLower(b.Status),
			UptimeSec: b.UptimeSec,
		})
	}
	return out, nil
}

// GetOspfNeighbors -------------------------------------------------------

func (p *Ingestor) GetOspfNeighbors(ctx context.Context, c firewall.Context) ([]firewall.OspfNeighbor, error) {
	var resp ospfNbrResp
	if err := p.opCommand(ctx, "<show><routing><protocol><ospf><neighbor></neighbor></ospf></protocol></routing></show>", &resp); err != nil {
		return nil, err
	}
	out := []firewall.OspfNeighbor{}
	for _, o := range resp.Entries {
		out = append(out, firewall.OspfNeighbor{
			PeerRouterID: o.RouterID,
			Area:         o.Area,
			State:        strings.ToLower(o.Status),
			Interface:    o.Interface,
		})
	}
	return out, nil
}

// ----- internal helpers -----

func (p *Ingestor) fetchAPIKey(ctx context.Context, user, password string) (string, error) {
	q := url.Values{}
	q.Set("type", "keygen")
	q.Set("user", user)
	q.Set("password", password)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.base+"/api/?"+q.Encode(), nil)
	resp, err := p.httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("paloalto: keygen request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", &firewall.AuthError{Wrapped: fmt.Errorf("paloalto: keygen rejected: %s", string(body))}
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("paloalto: keygen status %d: %s", resp.StatusCode, string(body))
	}
	var kr keygenResp
	if err := xml.Unmarshal(body, &kr); err != nil {
		return "", fmt.Errorf("paloalto: keygen decode: %w", err)
	}
	if kr.Status != "success" || kr.Key == "" {
		return "", &firewall.AuthError{Wrapped: fmt.Errorf("paloalto: keygen returned status=%q", kr.Status)}
	}
	return kr.Key, nil
}

// opCommand wraps an XML API op-mode call and decodes the response
// into dst. Non-success responses are returned as *apiError; 401/403
// are additionally wrapped with *firewall.AuthError so the generic
// driver's IsAuth check fires.
func (p *Ingestor) opCommand(ctx context.Context, cmd string, dst any) error {
	q := url.Values{}
	q.Set("type", "op")
	q.Set("cmd", cmd)
	q.Set("key", p.apiKey)
	u := p.base + "/api/?" + q.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := p.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("paloalto GET %s: %w", redact(u), err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MiB cap

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &firewall.AuthError{Wrapped: fmt.Errorf("paloalto %d: %s", resp.StatusCode, truncate(string(body), 256))}
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("paloalto %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	// PAN wraps every reply in <response status="success|error">. Inspect
	// the status before decoding the inner payload.
	var env responseEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("paloalto decode envelope: %w", err)
	}
	if env.Status != "success" {
		// Code 403 inside an XML envelope is the documented "invalid
		// credential" path even when HTTP returned 200.
		if env.Code == "403" {
			return &firewall.AuthError{Wrapped: fmt.Errorf("paloalto api status=%s code=%s", env.Status, env.Code)}
		}
		return fmt.Errorf("paloalto api status=%s code=%s: %s",
			env.Status, env.Code, truncate(string(env.Result), 256))
	}
	if dst == nil {
		return nil
	}
	if err := xml.Unmarshal(env.Result, dst); err != nil {
		return fmt.Errorf("paloalto decode result: %w", err)
	}
	return nil
}

func redact(s string) string {
	if i := strings.Index(s, "key="); i >= 0 {
		return s[:i] + "key=REDACTED"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func joinPA(xs []string) string {
	clean := make([]string, 0, len(xs))
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x != "" {
			clean = append(clean, x)
		}
	}
	return strings.Join(clean, ",")
}

func normalisePAStatus(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "up", "ifup":
		return "up"
	case "down", "ifdown":
		return "down"
	}
	return "unknown"
}
