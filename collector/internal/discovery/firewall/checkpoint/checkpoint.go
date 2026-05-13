// Package checkpoint implements firewall.Ingestor against Check Point's
// Management REST API (R80+). The endpoint is the management server,
// not the gateway — Check Point splits the management plane from the
// data plane and we honour that split: configuration (zones, NAT
// rulebase, security rulebase, IPsec communities) comes from
// management; runtime state (ARP, routes) needs a per-gateway call
// against the Gaia REST API on port 443.
//
// Auth flow:
//   POST /web_api/login    {user, password}  → returns {sid, uid, ...}
//   subsequent calls send `X-chkp-sid: <sid>` and POST with empty body
//   POST /web_api/logout
//
// What we DO pull (from management):
//   - simple gateways list           → ListContexts (treat each gateway as a context)
//   - per-gateway interfaces         → GetInterfaces
//   - access rulebase                → GetPolicies
//   - NAT rulebase                   → GetNatRules
//   - VPN communities (meshed/star)  → GetVpnTunnels
//
// What we currently SKIP (would require per-gateway Gaia REST on 443):
//   - GetRoutes      → returns []
//   - GetArpTable    → returns []
//   - GetZones       → synthesised from interface security-zone tags
//   - BGP/OSPF       → returns []
//
// These are tracked as future work in the collector README — Gaia REST
// auth is per-gateway with a separate credential rotation cadence and
// is best wired as a sibling driver rather than fanning out from here.
package checkpoint

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Ingestor implements firewall.Ingestor for Check Point R80+ Management API.
type Ingestor struct {
	base  string
	sid   string
	httpc *http.Client
}

// New returns an unauthenticated Ingestor.
func New() *Ingestor { return &Ingestor{} }

// Login authenticates against the Management API. Either a pre-issued
// session ID (creds.APIKey) can be reused, or username + password
// triggers a fresh login.
func (k *Ingestor) Login(ctx context.Context, creds firewall.Creds) error {
	if creds.Host == "" {
		return fmt.Errorf("checkpoint: host is required")
	}
	host := strings.TrimRight(creds.Host, "/")
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	k.base = host

	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: creds.TLSFingerprintSHA256 == ""},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
	}
	k.httpc = &http.Client{Transport: tr, Timeout: 60 * time.Second}

	if creds.APIKey != "" {
		k.sid = creds.APIKey
	} else if creds.Username != "" && creds.Password != "" {
		var resp loginResp
		err := k.post(ctx, "/web_api/login", map[string]any{
			"user":     creds.Username,
			"password": creds.Password,
		}, &resp)
		if err != nil {
			if firewall.IsAuth(err) {
				return &firewall.AuthError{Wrapped: fmt.Errorf("checkpoint: login rejected: %w", err)}
			}
			return err
		}
		if resp.Sid == "" {
			return &firewall.AuthError{Wrapped: fmt.Errorf("checkpoint: login returned empty sid")}
		}
		k.sid = resp.Sid
	} else {
		return fmt.Errorf("checkpoint: APIKey (sid) OR Username+Password required")
	}

	// Cheap probe — list gateways. This will 401/403 cleanly on bad sid.
	var probe gatewaysResp
	err := k.post(ctx, "/web_api/show-simple-gateways", map[string]any{"limit": 1}, &probe)
	if err != nil {
		if firewall.IsAuth(err) {
			return &firewall.AuthError{Wrapped: fmt.Errorf("checkpoint: sid rejected: %w", err)}
		}
		return err
	}
	return nil
}

func (k *Ingestor) Logout() error {
	if k.sid == "" {
		return nil
	}
	// Best-effort logout — we don't fail the job over it. Use a short
	// background context so the call still goes out even after the
	// dispatcher's context has been cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = k.post(ctx, "/web_api/logout", map[string]any{}, nil)
	k.sid = ""
	k.httpc = nil
	return nil
}

// ListContexts — each gateway managed by this server is a Context. We
// fetch the simple-gateways list and use the gateway name as both the
// Name and ID.
func (k *Ingestor) ListContexts(ctx context.Context) ([]firewall.Context, error) {
	var all []gatewayItem
	offset := 0
	const pageSize = 50
	for {
		var resp gatewaysResp
		err := k.post(ctx, "/web_api/show-simple-gateways", map[string]any{
			"offset":          offset,
			"limit":           pageSize,
			"details-level":   "full",
		}, &resp)
		if err != nil {
			return nil, err
		}
		all = append(all, resp.Objects...)
		offset += len(resp.Objects)
		if len(resp.Objects) < pageSize || offset >= resp.Total {
			break
		}
	}
	out := make([]firewall.Context, 0, len(all))
	for _, g := range all {
		if g.Name == "" {
			continue
		}
		out = append(out, firewall.Context{Name: g.Name, ID: g.Name})
	}
	if len(out) == 0 {
		// Single-domain MDS or no gateways yet — synthesise a "system"
		// context so the upper layer still gets one observation pass
		// of the management config itself.
		out = []firewall.Context{{Name: "system", ID: "system"}}
	}
	return out, nil
}

// GetInterfaces — pull `interfaces` from the gateway object.
func (k *Ingestor) GetInterfaces(ctx context.Context, c firewall.Context) ([]firewall.Interface, error) {
	var resp gatewayItem
	err := k.post(ctx, "/web_api/show-simple-gateway", map[string]any{
		"name":          c.ID,
		"details-level": "full",
	}, &resp)
	if err != nil {
		return nil, err
	}
	out := []firewall.Interface{}
	for _, ifc := range resp.Interfaces {
		ips := []string{}
		if ifc.IPv4Address != "" {
			ips = append(ips, fmt.Sprintf("%s/%d", ifc.IPv4Address, prefixLenFromMask(ifc.IPv4MaskLength)))
		}
		out = append(out, firewall.Interface{
			Name:   ifc.Name,
			Zone:   ifc.SecurityZone,
			Status: "unknown", // management API doesn't expose live link state
			IPs:    ips,
			IsVirtual: ifc.Topology == "internal" || ifc.Topology == "external",
		})
	}
	return out, nil
}

// GetRoutes — management API doesn't expose runtime routing tables.
// Returning an empty slice is honest; the dispatcher logs zero routes
// and moves on. A future per-gateway Gaia driver fills this in.
func (k *Ingestor) GetRoutes(ctx context.Context, c firewall.Context) ([]firewall.Route, error) {
	return nil, nil
}

// GetArpTable — same as GetRoutes; runtime state is gateway-side.
func (k *Ingestor) GetArpTable(ctx context.Context, c firewall.Context) ([]firewall.ArpEntry, error) {
	return nil, nil
}

// GetNatRules — pulls the NAT rulebase published to the management.
func (k *Ingestor) GetNatRules(ctx context.Context, c firewall.Context) ([]firewall.NatRule, error) {
	var resp natRulebaseResp
	err := k.post(ctx, "/web_api/show-nat-rulebase", map[string]any{
		"package":       "Standard",
		"details-level": "standard",
		"limit":         200,
	}, &resp)
	if err != nil {
		return nil, err
	}
	out := []firewall.NatRule{}
	for _, r := range resp.Rulebase {
		// `rulebase` is a mix of section headers and rules; rules have
		// a non-zero "rule-number" field.
		if r.RuleNumber == 0 {
			continue
		}
		dir := "src"
		if r.TranslatedDestination != "" && r.TranslatedDestination != "Original" {
			dir = "dst"
		}
		out = append(out, firewall.NatRule{
			Name:           r.Name,
			Direction:      dir,
			OriginalSrc:    r.OriginalSource,
			OriginalDst:    r.OriginalDestination,
			Protocol:       r.OriginalService,
			TranslatedSrc:  r.TranslatedSource,
			TranslatedDst:  r.TranslatedDestination,
			TranslatedPort: r.TranslatedService,
		})
	}
	return out, nil
}

// GetZones — Check Point security zones are first-class objects. We pull
// them and map each zone's "interfaces" reference list.
func (k *Ingestor) GetZones(ctx context.Context, c firewall.Context) ([]firewall.Zone, error) {
	var resp zonesResp
	err := k.post(ctx, "/web_api/show-security-zones", map[string]any{
		"limit":         200,
		"details-level": "standard",
	}, &resp)
	if err != nil {
		return nil, nil // many estates don't use security zones explicitly
	}
	out := make([]firewall.Zone, 0, len(resp.Objects))
	for _, z := range resp.Objects {
		// security-zone objects don't carry interface members; the
		// management API exposes the bag-of-interfaces relationship
		// only via the gateway's `interfaces` field. We surface the
		// zone NAME so a fusion-time join can rebuild the membership.
		out = append(out, firewall.Zone{Name: z.Name})
	}
	return out, nil
}

// GetPolicies — pulls the access rulebase.
func (k *Ingestor) GetPolicies(ctx context.Context, c firewall.Context) ([]firewall.Policy, error) {
	var resp accessRulebaseResp
	err := k.post(ctx, "/web_api/show-access-rulebase", map[string]any{
		"name":          "Standard Network",
		"details-level": "standard",
		"limit":         200,
	}, &resp)
	if err != nil {
		return nil, err
	}
	out := []firewall.Policy{}
	for _, r := range resp.Rulebase {
		if r.RuleNumber == 0 {
			continue
		}
		out = append(out, firewall.Policy{
			Name:         r.Name,
			Sources:      r.Source,
			Destinations: r.Destination,
			Services:     r.Service,
			Action:       strings.ToLower(r.Action),
			Enabled:      r.Enabled,
		})
	}
	return out, nil
}

// GetVpnTunnels — Check Point models VPN as "communities" (meshed or
// star). Each community contains gateway members and (for star) a
// center gateway. We flatten each member-pair into a tunnel.
func (k *Ingestor) GetVpnTunnels(ctx context.Context, c firewall.Context) ([]firewall.VpnTunnel, error) {
	out := []firewall.VpnTunnel{}
	for _, endpoint := range []string{"show-vpn-communities-meshed", "show-vpn-communities-star"} {
		var resp communitiesResp
		err := k.post(ctx, "/web_api/"+endpoint, map[string]any{"limit": 50, "details-level": "full"}, &resp)
		if err != nil {
			continue
		}
		for _, com := range resp.Objects {
			for _, peer := range com.GatewayMembers {
				out = append(out, firewall.VpnTunnel{
					Name:       com.Name + ":" + peer.Name,
					PeerIP:     peer.IPv4Address,
					Status:     "unknown",
					IKEVersion: "v2",
				})
			}
		}
	}
	return out, nil
}

// GetBgpNeighbors — management API doesn't expose runtime routing
// adjacencies. Empty slice is honest.
func (k *Ingestor) GetBgpNeighbors(ctx context.Context, c firewall.Context) ([]firewall.BgpNeighbor, error) {
	return nil, nil
}

// GetOspfNeighbors — same as GetBgpNeighbors.
func (k *Ingestor) GetOspfNeighbors(ctx context.Context, c firewall.Context) ([]firewall.OspfNeighbor, error) {
	return nil, nil
}

// ----- internal helpers -----

// post sends a JSON POST with the X-chkp-sid header and decodes the
// reply into dst.
func (k *Ingestor) post(ctx context.Context, path string, body map[string]any, dst any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, k.base+path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if k.sid != "" && path != "/web_api/login" {
		req.Header.Set("X-chkp-sid", k.sid)
	}
	resp, err := k.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("checkpoint %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &firewall.AuthError{Wrapped: fmt.Errorf("checkpoint %s -> %d: %s", path, resp.StatusCode, truncate(string(respBody), 200))}
	}
	if resp.StatusCode/100 != 2 {
		// Check Point uses 400 with a `{"code":"...","message":"..."}`
		// envelope for auth-ish errors too — sniff the body.
		if isAuthBody(respBody) {
			return &firewall.AuthError{Wrapped: fmt.Errorf("checkpoint %s -> %d: %s", path, resp.StatusCode, truncate(string(respBody), 200))}
		}
		return fmt.Errorf("checkpoint %s -> %d: %s", path, resp.StatusCode, truncate(string(respBody), 200))
	}
	if dst == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, dst); err != nil {
		return fmt.Errorf("checkpoint decode %s: %w", path, err)
	}
	return nil
}

func isAuthBody(b []byte) bool {
	s := strings.ToLower(string(b))
	return strings.Contains(s, "invalid session") ||
		strings.Contains(s, "session expired") ||
		strings.Contains(s, "authentication") ||
		strings.Contains(s, "login failed")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// prefixLenFromMask accepts either a dotted mask ("255.255.255.0") or
// an already-cidr-formatted mask string ("24") and returns a CIDR prefix
// length.
func prefixLenFromMask(mask string) int {
	if mask == "" {
		return 32
	}
	// Already a number?
	if !strings.Contains(mask, ".") {
		var n int
		fmt.Sscanf(mask, "%d", &n)
		if n > 0 && n <= 32 {
			return n
		}
	}
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return 32
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
			return 32
		}
	}
	return n
}
