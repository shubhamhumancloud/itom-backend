// FortiGate REST response shapes. Only the fields we map to firewall
// payload types are decoded — every other field in the JSON is ignored,
// so future FortiOS additions don't break us.
package fortigate

// envelope is the outer wrapper FortiOS returns on /api/v2/cmdb and
// /api/v2/monitor endpoints. `results` is the meaningful payload; the
// rest is metadata we don't need for ingestion.
type envelope[T any] struct {
	Status  string `json:"status"`
	VDOM    string `json:"vdom"`
	Results T      `json:"results"`
}

// pageEnvelope is the variant returned by paginated endpoints. `total`
// drives the pagination loop.
type pageEnvelope[T any] struct {
	Status  string `json:"status"`
	VDOM    string `json:"vdom"`
	Results T      `json:"results"`
	Total   int    `json:"total"`
	Size    int    `json:"size"`
}

// VDOM list — /api/v2/cmdb/system/vdom
type vdomRow struct {
	Name string `json:"name"`
}

// Interface — /api/v2/monitor/system/interface (status + IPs together)
type ifaceRow struct {
	Name      string `json:"name"`
	Alias     string `json:"alias"`
	Status    string `json:"status"`     // "up" | "down"
	Mode      string `json:"mode"`       // "static" | "dhcp" | …
	MAC       string `json:"mac_address"`
	IP        string `json:"ip"`         // "10.0.0.1 255.255.255.0"
	IPv4Addresses []struct {
		IP      string `json:"ip"`
		Mask    string `json:"mask"`
		Netmask string `json:"netmask"`
	} `json:"ipv4_addresses"`
	Zone   string `json:"zone"`
	Vlanid int    `json:"vlanid"`
	Type   string `json:"type"`
}

// Route — /api/v2/monitor/router/ipv4
type routeRow struct {
	IPVersion int    `json:"ip_version"`
	Type      string `json:"type"`       // "static" | "connect" | "bgp" | "ospf"
	IPMask    string `json:"ip_mask"`    // "10.20.0.0/16"
	Gateway   string `json:"gateway"`
	Distance  int    `json:"distance"`
	Metric    int    `json:"metric"`
	Interface string `json:"interface"`
	VRF       int    `json:"vrf"`
}

// ARP — /api/v2/monitor/network/arp
type arpRow struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
	Age       int    `json:"age"`
}

// NAT — /api/v2/cmdb/firewall/policy (NAT is a flag on policies in FortiOS;
// VIPs are their own endpoint we also pull below).
type policyRow struct {
	PolicyID   int      `json:"policyid"`
	Name       string   `json:"name"`
	SrcIntf    []namedRef `json:"srcintf"`
	DstIntf    []namedRef `json:"dstintf"`
	SrcAddr    []namedRef `json:"srcaddr"`
	DstAddr    []namedRef `json:"dstaddr"`
	Service    []namedRef `json:"service"`
	Action     string   `json:"action"` // "accept" | "deny"
	Status     string   `json:"status"` // "enable" | "disable"
	NAT        string   `json:"nat"`    // "enable" | "disable"
	IPPool     string   `json:"ippool"` // "enable" | "disable"
	PoolName   []namedRef `json:"poolname"`
}

type namedRef struct {
	Name string `json:"name"`
}

// VIP — /api/v2/cmdb/firewall/vip
type vipRow struct {
	Name        string `json:"name"`
	ExtIP       string `json:"extip"`        // "203.0.113.10"
	Mappedip    []struct {
		Range string `json:"range"`
	} `json:"mappedip"`
	ExtPort     string `json:"extport"`      // "443" or "0" for any
	MappedPort  string `json:"mappedport"`
	Protocol    string `json:"protocol"`     // "tcp" | "udp" | "sctp" | "icmp"
	PortForward string `json:"portforward"`  // "enable" | "disable"
}

// Zone — /api/v2/cmdb/system/zone
type zoneRow struct {
	Name      string     `json:"name"`
	Interface []namedRef `json:"interface"`
}

// IPsec phase1 (config) — /api/v2/cmdb/vpn.ipsec/phase1-interface
type phase1Row struct {
	Name       string `json:"name"`
	Interface  string `json:"interface"`
	RemoteGW   string `json:"remote-gw"`
	IKEVersion string `json:"ike-version"`
}

// IPsec phase2 (config) — /api/v2/cmdb/vpn.ipsec/phase2-interface — gives
// us the proxy-IDs (the subnet binding). Each phase2 is anchored to a
// phase1 via the `phase1name` field.
type phase2Row struct {
	Name        string `json:"name"`
	Phase1Name  string `json:"phase1name"`
	SrcSubnet   string `json:"src-subnet"`   // "10.0.0.0 255.255.0.0"
	DstSubnet   string `json:"dst-subnet"`
	SrcAddrType string `json:"src-addr-type"`
	DstAddrType string `json:"dst-addr-type"`
}

// IPsec tunnel live status — /api/v2/monitor/vpn/ipsec
type ipsecMonitorRow struct {
	Name       string `json:"name"`
	Phase1Name string `json:"p1name"`
	IncomingBytes int64 `json:"incoming_bytes"`
	OutgoingBytes int64 `json:"outgoing_bytes"`
	Status     string `json:"status"` // "up" | "down"
	ProxyID    []struct {
		ProxySrc []struct {
			Subnet string `json:"subnet"`
		} `json:"proxy_src"`
		ProxyDst []struct {
			Subnet string `json:"subnet"`
		} `json:"proxy_dst"`
		Status string `json:"status"`
	} `json:"proxyid"`
}

// BGP neighbor — /api/v2/monitor/router/bgp/neighbors
type bgpRow struct {
	NeighborIP string `json:"neighbor_ip"`
	RemoteAS   int    `json:"remote_as"`
	LocalAS    int    `json:"local_as"`
	State      string `json:"state"`
	UptimeSec  int64  `json:"uptime"`
}

// OSPF neighbor — /api/v2/monitor/router/ospf/neighbors
type ospfRow struct {
	NeighborID string `json:"neighbor_id"`
	IP         string `json:"ip"`
	State      string `json:"state"`
	Area       string `json:"area"`
	Interface  string `json:"interface"`
}
