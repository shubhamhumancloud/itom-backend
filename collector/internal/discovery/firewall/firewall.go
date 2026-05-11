// Package firewall declares the vendor-neutral interface every supported
// firewall implementation (FortiGate, Palo Alto, Check Point, Cisco ASA)
// satisfies. The collector's job dispatcher selects an implementation per
// scan-job target and then never knows which vendor it's talking to.
//
// Payload types are deliberately minimal: each row carries only the
// fields we map to an observation. Vendor-specific extras stay in the
// implementation package and are dropped before they cross this boundary.
package firewall

import "context"

// Creds is the set of inputs an Ingestor needs to authenticate. Concrete
// implementations pick the fields they care about (e.g. FortiGate uses
// only APIKey; ASA uses Username/Password).
type Creds struct {
	Host     string
	Username string
	Password string
	APIKey   string
	// TLSFingerprintSHA256 pins the firewall's self-signed cert. Empty means
	// rely on the system trust store (only safe for lab gear).
	TLSFingerprintSHA256 string
}

// Context represents one virtual firewall — vsys / VDOM / context / VSX
// virtual system. Single-context boxes still return one Context whose Name
// is the vendor default ("root" / "vsys1" / "VS0" / "system").
type Context struct {
	Name string
	// Vendor-specific id used in URL params (vdom name, vsid number, etc.).
	ID string
}

// Interface is one physical or logical port on the firewall.
type Interface struct {
	Name     string   // "port1", "ethernet1/3", "vlan100"
	Zone     string   // "trust", "untrust", "dmz"; empty if unzoned
	Status   string   // "up" | "down" | "unknown"
	IPs      []string // CIDR-formatted ("10.0.0.1/24")
	MAC      string
	VlanID   int  // 0 if untagged
	IsVirtual bool // true for VLAN / loopback / aggregate
}

// Route is one row from the routing table.
type Route struct {
	VirtualRouter string // "default" on single-VR boxes
	Prefix        string // "10.20.0.0/16"
	NextHop       string // "10.0.0.1" or empty for connected
	Interface     string
	Protocol      string // "connected" | "static" | "bgp" | "ospf" | ...
	Distance      int
	Metric        int
}

// ArpEntry is one row from the ARP table — proof that a host has been
// actively reachable through the firewall recently.
type ArpEntry struct {
	IP        string
	MAC       string
	Interface string
}

// NatRule is one rule from the NAT table. Direction is one of "src"
// (SNAT — many internal IPs masquerade as one external) or "dst" (DNAT
// / VIP — one external IP+port forwards to one internal IP+port).
type NatRule struct {
	Name         string
	Direction    string // "src" | "dst"
	OriginalSrc  string // CIDR or IP
	OriginalDst  string
	OriginalPort string // "443" or "" if any
	Protocol     string // "tcp" | "udp" | "any"
	TranslatedSrc  string
	TranslatedDst  string
	TranslatedPort string
}

// Zone is a named bag of interfaces.
type Zone struct {
	Name       string
	Interfaces []string
}

// Policy is one inter-zone rule. Source/Destination/Service can each be
// either a literal value or a vendor object name we resolve later.
type Policy struct {
	Name        string
	FromZone    string
	ToZone      string
	Sources     []string
	Destinations []string
	Services    []string
	Action      string // "accept" | "deny" | "drop"
	Enabled     bool
}

// VpnTunnel is one IPsec site-to-site tunnel and the subnets it binds.
type VpnTunnel struct {
	Name        string
	PeerIP      string
	LocalSubnets  []string
	RemoteSubnets []string
	Status      string // "up" | "down" | "unknown"
	IKEVersion  string
}

// BgpNeighbor is one BGP peer relationship.
type BgpNeighbor struct {
	PeerIP    string
	PeerAS    int
	LocalAS   int
	State     string // "established" | "active" | ...
	UptimeSec int64
}

// OspfNeighbor is one OSPF adjacency.
type OspfNeighbor struct {
	PeerRouterID string
	Area         string
	State        string // "full" | "2-way" | ...
	Interface    string
}

// Ingestor is the contract every vendor implementation satisfies.
//
// Methods are called in a fixed sequence per Context: Login → ListContexts
// → (for each ctx) all Get*. Logout runs once at end-of-job. Implementations
// must be safe for use by a single goroutine — the dispatcher serialises
// calls per firewall to respect vendor management-plane rate caps.
type Ingestor interface {
	Login(ctx context.Context, creds Creds) error
	ListContexts(ctx context.Context) ([]Context, error)

	GetInterfaces(ctx context.Context, c Context) ([]Interface, error)
	GetRoutes(ctx context.Context, c Context) ([]Route, error)
	GetArpTable(ctx context.Context, c Context) ([]ArpEntry, error)
	GetNatRules(ctx context.Context, c Context) ([]NatRule, error)
	GetZones(ctx context.Context, c Context) ([]Zone, error)
	GetPolicies(ctx context.Context, c Context) ([]Policy, error)
	GetVpnTunnels(ctx context.Context, c Context) ([]VpnTunnel, error)
	GetBgpNeighbors(ctx context.Context, c Context) ([]BgpNeighbor, error)
	GetOspfNeighbors(ctx context.Context, c Context) ([]OspfNeighbor, error)

	Logout() error
}

// Vendor enumerates the supported firewall families. Used by the
// dispatcher to pick a constructor.
type Vendor string

const (
	VendorFortiGate  Vendor = "fortigate"
	VendorPaloAlto   Vendor = "paloalto"
	VendorCheckPoint Vendor = "checkpoint"
	VendorCiscoASA   Vendor = "cisco_asa"
)
