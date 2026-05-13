// Package cisco_asa implements firewall.Ingestor against Cisco ASA's
// REST API (introduced in 9.3, default-on in 9.6+).
//
// Auth: HTTP Basic with a read-only RADIUS/local user. We do NOT log in
// as `enable`-privileged users. Some ASA fleets disable the REST API
// entirely; for those, an SSH/CLI driver is the right fallback — out
// of scope here, tracked as a future driver.
//
// Endpoint layout (all under /api):
//   /api/interfaces/physical
//   /api/interfaces/vlan
//   /api/routing/static
//   /api/monitoring/arp
//   /api/nat/twice                (modern Twice-NAT)
//   /api/objects/securityobjectgroups   (zones — ASA "security level" maps)
//   /api/access/in/{ifc}/rules    (per-interface ACLs — analogue of policy)
//   /api/monitoring/vpn/lan       (IPsec site-to-site SAs)
//
// What we deliberately do NOT pull:
//   - the connection table (`show conn`) — millions of rows
//   - syslog / threat detection events
//   - dynamic NAT translation table (xlate) — operational noise
package cisco_asa

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/itom-mini/collector/internal/discovery/firewall"
)

// Ingestor implements firewall.Ingestor for Cisco ASA REST.
type Ingestor struct {
	base       string
	authHeader string // pre-built "Basic <b64(u:p)>"
	httpc      *http.Client
}

// New returns an unauthenticated Ingestor.
func New() *Ingestor { return &Ingestor{} }

// Login validates the basic-auth credential by hitting /api/aaa/authentication/serverstatus
// (cheap, returns 401 quickly when the user/password is wrong). We do not
// keep a session token — ASA REST is HTTP Basic on every call.
func (a *Ingestor) Login(ctx context.Context, creds firewall.Creds) error {
	if creds.Host == "" {
		return fmt.Errorf("cisco_asa: host is required")
	}
	if creds.Username == "" || creds.Password == "" {
		return fmt.Errorf("cisco_asa: username + password required")
	}
	host := strings.TrimRight(creds.Host, "/")
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	a.base = host
	a.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(creds.Username+":"+creds.Password))

	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: creds.TLSFingerprintSHA256 == ""},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
	}
	a.httpc = &http.Client{Transport: tr, Timeout: 60 * time.Second}

	// Cheap auth probe. /api/monitoring/device gives back the hostname
	// and version on success and 401 on bad creds.
	var dev deviceMonitor
	if err := a.get(ctx, "/api/monitoring/device", &dev); err != nil {
		if firewall.IsAuth(err) {
			return &firewall.AuthError{Wrapped: fmt.Errorf("cisco_asa: credentials rejected: %w", err)}
		}
		return err
	}
	return nil
}

func (a *Ingestor) Logout() error {
	// Basic auth — no session to revoke.
	a.httpc = nil
	a.authHeader = ""
	return nil
}

// ListContexts — ASA "multi-context mode" splits the box into virtual
// firewalls. The REST API exposes /api/admin/contexts in multi-context
// mode; in single-context mode (the common case) we return one
// synthetic "system" context.
func (a *Ingestor) ListContexts(ctx context.Context) ([]firewall.Context, error) {
	var resp itemsEnvelope[contextItem]
	err := a.get(ctx, "/api/admin/contexts?offset=0&limit=100", &resp)
	if err != nil || len(resp.Items) == 0 {
		// Single-context mode — synthesise one entry.
		return []firewall.Context{{Name: "system", ID: "system"}}, nil
	}
	out := make([]firewall.Context, 0, len(resp.Items))
	for _, c := range resp.Items {
		if c.Name == "" {
			continue
		}
		out = append(out, firewall.Context{Name: c.Name, ID: c.Name})
	}
	return out, nil
}

// GetInterfaces ----------------------------------------------------------

func (a *Ingestor) GetInterfaces(ctx context.Context, c firewall.Context) ([]firewall.Interface, error) {
	out := []firewall.Interface{}

	// Physical interfaces.
	var phys itemsEnvelope[interfaceItem]
	if err := a.getAll(ctx, "/api/interfaces/physical", &phys); err != nil {
		return nil, err
	}
	for _, i := range phys.Items {
		out = append(out, mapInterface(i, false))
	}

	// VLAN sub-interfaces.
	var vlans itemsEnvelope[interfaceItem]
	if err := a.getAll(ctx, "/api/interfaces/vlan", &vlans); err == nil {
		for _, i := range vlans.Items {
			out = append(out, mapInterface(i, true))
		}
	}
	return out, nil
}

// GetRoutes --------------------------------------------------------------
//
// ASA REST only exposes the static-route table. Dynamic routes (BGP,
// OSPF) require `/api/monitoring/route` which exists on 9.7+ — we try
// that first and fall back to static-only.
func (a *Ingestor) GetRoutes(ctx context.Context, c firewall.Context) ([]firewall.Route, error) {
	out := []firewall.Route{}

	// Operational view (preferred).
	var routes itemsEnvelope[routeItem]
	if err := a.getAll(ctx, "/api/monitoring/routing/routes", &routes); err == nil {
		for _, r := range routes.Items {
			out = append(out, firewall.Route{
				VirtualRouter: "default",
				Prefix:        cidrFromNetmask(r.Network, r.Netmask),
				NextHop:       r.Gateway,
				Interface:     r.Interface,
				Protocol:      strings.ToLower(r.Protocol),
				Metric:        r.Metric,
			})
		}
		return out, nil
	}

	// Static-only fallback.
	var statics itemsEnvelope[staticRouteItem]
	if err := a.getAll(ctx, "/api/routing/static", &statics); err != nil {
		return nil, err
	}
	for _, r := range statics.Items {
		out = append(out, firewall.Route{
			VirtualRouter: "default",
			Prefix:        cidrFromObjectRef(r.NetworkObject),
			NextHop:       r.Gateway.Value,
			Interface:     r.Interface.Name,
			Protocol:      "static",
			Metric:        r.Metric,
		})
	}
	return out, nil
}

// GetArpTable ------------------------------------------------------------

func (a *Ingestor) GetArpTable(ctx context.Context, c firewall.Context) ([]firewall.ArpEntry, error) {
	var resp itemsEnvelope[arpItem]
	if err := a.getAll(ctx, "/api/monitoring/arp", &resp); err != nil {
		return nil, err
	}
	out := make([]firewall.ArpEntry, 0, len(resp.Items))
	for _, e := range resp.Items {
		out = append(out, firewall.ArpEntry{
			IP:        e.IPAddress,
			MAC:       e.MACAddress,
			Interface: e.Interface,
		})
	}
	return out, nil
}

// GetNatRules ------------------------------------------------------------

func (a *Ingestor) GetNatRules(ctx context.Context, c firewall.Context) ([]firewall.NatRule, error) {
	var resp itemsEnvelope[twiceNatItem]
	if err := a.getAll(ctx, "/api/nat/twice", &resp); err != nil {
		return nil, err
	}
	out := make([]firewall.NatRule, 0, len(resp.Items))
	for _, r := range resp.Items {
		dir := "src"
		if r.OriginalDestination.Value != "" || r.TranslatedDestination.Value != "" {
			dir = "dst"
		}
		out = append(out, firewall.NatRule{
			Name:           fmt.Sprintf("twice-nat-%d", r.Position),
			Direction:      dir,
			OriginalSrc:    r.OriginalSource.Value,
			OriginalDst:    r.OriginalDestination.Value,
			OriginalPort:   r.OriginalService.Value,
			Protocol:       strings.ToLower(r.OriginalService.Protocol),
			TranslatedSrc:  r.TranslatedSource.Value,
			TranslatedDst:  r.TranslatedDestination.Value,
			TranslatedPort: r.TranslatedService.Value,
		})
	}
	return out, nil
}

// GetZones — ASA has no "zone" object; the closest analogue is the
// per-interface security-level. We synthesise one zone per security
// level that has interfaces assigned to it.
func (a *Ingestor) GetZones(ctx context.Context, c firewall.Context) ([]firewall.Zone, error) {
	var phys itemsEnvelope[interfaceItem]
	if err := a.getAll(ctx, "/api/interfaces/physical", &phys); err != nil {
		return nil, err
	}
	bySec := map[int][]string{}
	for _, i := range phys.Items {
		bySec[i.SecurityLevel] = append(bySec[i.SecurityLevel], i.HardwareID)
	}
	out := make([]firewall.Zone, 0, len(bySec))
	for lvl, ifs := range bySec {
		out = append(out, firewall.Zone{
			Name:       fmt.Sprintf("security-level-%d", lvl),
			Interfaces: ifs,
		})
	}
	return out, nil
}

// GetPolicies — ASA per-interface inbound ACLs are the closest analogue
// to a security policy. We iterate every interface and pull its ACL.
// Many small boxes have these only on the "outside" interface; that's
// fine — the policy list just ends up short.
func (a *Ingestor) GetPolicies(ctx context.Context, c firewall.Context) ([]firewall.Policy, error) {
	var phys itemsEnvelope[interfaceItem]
	if err := a.getAll(ctx, "/api/interfaces/physical", &phys); err != nil {
		return nil, err
	}
	out := []firewall.Policy{}
	for _, ifc := range phys.Items {
		if ifc.Name == "" {
			continue
		}
		var rules itemsEnvelope[aclRuleItem]
		path := fmt.Sprintf("/api/access/in/%s/rules", ifc.Name)
		if err := a.getAll(ctx, path, &rules); err != nil {
			// Many interfaces have no inbound ACL — skip silently.
			continue
		}
		for _, r := range rules.Items {
			out = append(out, firewall.Policy{
				Name:         fmt.Sprintf("%s-in-%d", ifc.Name, r.Position),
				FromZone:     ifc.Name,
				ToZone:       "",
				Sources:      []string{r.SourceAddress.Value},
				Destinations: []string{r.DestinationAddress.Value},
				Services:     []string{r.DestinationService.Value},
				Action:       strings.ToLower(r.Permit),
				Enabled:      r.Active,
			})
		}
	}
	return out, nil
}

// GetVpnTunnels ----------------------------------------------------------

func (a *Ingestor) GetVpnTunnels(ctx context.Context, c firewall.Context) ([]firewall.VpnTunnel, error) {
	var resp itemsEnvelope[lanVpnItem]
	if err := a.getAll(ctx, "/api/monitoring/vpn/lan", &resp); err != nil {
		return nil, err
	}
	out := make([]firewall.VpnTunnel, 0, len(resp.Items))
	for _, t := range resp.Items {
		out = append(out, firewall.VpnTunnel{
			Name:          t.IPAddress,
			PeerIP:        t.IPAddress,
			LocalSubnets:  t.LocalNetworks,
			RemoteSubnets: t.RemoteNetworks,
			Status:        "up",
			IKEVersion:    t.IKEVersion,
		})
	}
	return out, nil
}

// GetBgpNeighbors --------------------------------------------------------
//
// ASA does support BGP but the REST surface is incomplete on older
// versions. We try /api/monitoring/routing/bgp/neighbors and degrade
// gracefully to an empty list.
func (a *Ingestor) GetBgpNeighbors(ctx context.Context, c firewall.Context) ([]firewall.BgpNeighbor, error) {
	var resp itemsEnvelope[bgpNeighborItem]
	if err := a.getAll(ctx, "/api/monitoring/routing/bgp/neighbors", &resp); err != nil {
		return nil, nil // best-effort
	}
	out := make([]firewall.BgpNeighbor, 0, len(resp.Items))
	for _, b := range resp.Items {
		out = append(out, firewall.BgpNeighbor{
			PeerIP:    b.NeighborAddress,
			PeerAS:    b.RemoteAS,
			State:     strings.ToLower(b.State),
			UptimeSec: b.UpTime,
		})
	}
	return out, nil
}

// GetOspfNeighbors -------------------------------------------------------

func (a *Ingestor) GetOspfNeighbors(ctx context.Context, c firewall.Context) ([]firewall.OspfNeighbor, error) {
	var resp itemsEnvelope[ospfNeighborItem]
	if err := a.getAll(ctx, "/api/monitoring/routing/ospf/neighbors", &resp); err != nil {
		return nil, nil
	}
	out := make([]firewall.OspfNeighbor, 0, len(resp.Items))
	for _, o := range resp.Items {
		out = append(out, firewall.OspfNeighbor{
			PeerRouterID: o.NeighborID,
			Area:         o.Area,
			State:        strings.ToLower(o.State),
			Interface:    o.Interface,
		})
	}
	return out, nil
}

// ----- internal helpers -----

func (a *Ingestor) get(ctx context.Context, path string, dst any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	req.Header.Set("Authorization", a.authHeader)
	req.Header.Set("Accept", "application/json")
	resp, err := a.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("cisco_asa %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))

	if resp.StatusCode == http.StatusUnauthorized {
		return &firewall.AuthError{Wrapped: fmt.Errorf("cisco_asa %s -> 401", path)}
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("cisco_asa %s -> %d: %s", path, resp.StatusCode, truncate(string(body), 200))
	}
	if dst == nil {
		return nil
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("cisco_asa decode %s: %w", path, err)
	}
	return nil
}

// getAll walks a paginated collection. ASA REST returns items in pages
// of 100 by default with a `rangeInfo.total` field telling us when to
// stop.
func (a *Ingestor) getAll(ctx context.Context, basePath string, dst rangePager) error {
	const pageSize = 100
	offset := 0
	for {
		sep := "?"
		if strings.Contains(basePath, "?") {
			sep = "&"
		}
		path := fmt.Sprintf("%s%soffset=%d&limit=%d", basePath, sep, offset, pageSize)
		if err := a.get(ctx, path, dst); err != nil {
			return err
		}
		got := dst.pageLen()
		offset += got
		if got < pageSize || offset >= dst.totalCount() {
			return nil
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---- field mappers ----

func mapInterface(i interfaceItem, isVirtual bool) firewall.Interface {
	ips := []string{}
	if i.IPAddress.IP.Value != "" {
		ips = append(ips, cidrFromNetmask(i.IPAddress.IP.Value, i.IPAddress.Netmask.Value))
	}
	return firewall.Interface{
		Name:      defaultName(i.Name, i.HardwareID),
		Zone:      fmt.Sprintf("security-level-%d", i.SecurityLevel),
		Status:    normaliseStatus(i),
		IPs:       ips,
		MAC:       i.MACAddress,
		VlanID:    i.VLANID,
		IsVirtual: isVirtual,
	}
}

func defaultName(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func normaliseStatus(i interfaceItem) string {
	if i.Shutdown {
		return "down"
	}
	if i.LinkStatus == "up" {
		return "up"
	}
	if i.LinkStatus == "down" {
		return "down"
	}
	return "unknown"
}

// cidrFromNetmask combines an IP + dotted-quad mask into a CIDR string.
// We do dumb string math (not net.IPNet) to keep this dependency-free
// and to tolerate ASA returning the netmask in unusual forms.
func cidrFromNetmask(ip, mask string) string {
	if ip == "" {
		return ""
	}
	if mask == "" {
		return ip
	}
	bits := maskBits(mask)
	if bits < 0 {
		return fmt.Sprintf("%s %s", ip, mask)
	}
	return fmt.Sprintf("%s/%d", ip, bits)
}

func maskBits(m string) int {
	parts := strings.Split(m, ".")
	if len(parts) != 4 {
		return -1
	}
	var n int
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
			return -1
		}
	}
	return n
}

func cidrFromObjectRef(o objectRef) string {
	if o.Value != "" {
		return o.Value
	}
	if o.RefLink != "" {
		// Object reference — fully resolving requires another call. For
		// now we surface the object name; fusion can resolve if needed.
		return o.Name
	}
	return ""
}
