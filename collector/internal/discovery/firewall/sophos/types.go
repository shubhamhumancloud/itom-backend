package sophos

import "encoding/xml"

// responseEnvelope is the outer wrapper every Sophos XML reply uses.
// We unmarshal this first to inspect <Login><status> before decoding
// the call-specific body.
type responseEnvelope struct {
	XMLName    xml.Name `xml:"Response"`
	APIVersion string   `xml:"APIVersion,attr"`
	Login      struct {
		Status string `xml:"status"`
	} `xml:"Login"`
}

// ---- interfaces ----

type interfaceResp struct {
	XMLName    xml.Name        `xml:"Response"`
	Interfaces []interfaceItem `xml:"Interface"`
}

type interfaceItem struct {
	Name          string `xml:"Name"`
	HardwareName  string `xml:"HardwareName"`
	Status        string `xml:"Status"`
	IPAddress     string `xml:"IPAddress"`
	Netmask       string `xml:"Netmask"`
	Zone          string `xml:"Zone"`
	MACAddress    string `xml:"MACAddress"`
	InterfaceType string `xml:"InterfaceType"`
}

// ---- routes (static) ----

type unicastRouteResp struct {
	XMLName xml.Name       `xml:"Response"`
	Routes  []unicastRoute `xml:"UnicastRoute"`
}

type unicastRoute struct {
	DstNetwork string `xml:"DstNetwork"`
	DstNetmask string `xml:"DstNetmask"`
	Gateway    string `xml:"Gateway"`
	Interface  string `xml:"Interface"`
	Distance   int    `xml:"Distance"`
}

// ---- NAT rules ----

type natRuleResp struct {
	XMLName  xml.Name      `xml:"Response"`
	NATRules []natRuleItem `xml:"NATRule"`
}

type natRuleItem struct {
	Name                   string   `xml:"Name"`
	OriginalSource         []string `xml:"OriginalSourceNetworks>Network"`
	OriginalDestination    []string `xml:"OriginalDestinationNetworks>Network"`
	OriginalService        []string `xml:"OriginalServices>Service"`
	SourceTranslation      string   `xml:"TranslatedSource"`
	DestinationTranslation string   `xml:"TranslatedDestination"`
	ServiceTranslation     string   `xml:"TranslatedService"`
}

// ---- zones ----

type zoneResp struct {
	XMLName xml.Name   `xml:"Response"`
	Zones   []zoneItem `xml:"Zone"`
}

type zoneItem struct {
	Name    string   `xml:"Name"`
	Members []string `xml:"Members>Member"`
}

// ---- firewall rules ----

type firewallRuleResp struct {
	XMLName xml.Name           `xml:"Response"`
	Rules   []firewallRuleItem `xml:"FirewallRule"`
}

type firewallRuleItem struct {
	Name          string `xml:"Name"`
	Status        string `xml:"Status"`
	NetworkPolicy struct {
		SourceZones         []string `xml:"SourceZones>Zone"`
		DestinationZones    []string `xml:"DestinationZones>Zone"`
		SourceNetworks      []string `xml:"SourceNetworks>Network"`
		DestinationNetworks []string `xml:"DestinationNetworks>Network"`
		Services            []string `xml:"Services>Service"`
		Action              string   `xml:"Action"`
	} `xml:"NetworkPolicy"`
}

// ---- IPsec ----

type ipsecResp struct {
	XMLName     xml.Name    `xml:"Response"`
	Connections []ipsecItem `xml:"VPNIPSecConnection"`
}

type ipsecItem struct {
	Name             string   `xml:"Name"`
	RemoteGateway    string   `xml:"RemoteGateway"`
	LocalSubnets     []string `xml:"LocalSubnets>LocalSubnet"`
	RemoteSubnets    []string `xml:"RemoteSubnets>RemoteSubnet"`
	ConnectionStatus string   `xml:"ConnectionStatus"`
	IKEVersion       string   `xml:"IKEVersion"`
}

// ---- BGP ----

type bgpNeighborResp struct {
	XMLName   xml.Name          `xml:"Response"`
	Neighbors []bgpNeighborItem `xml:"BGPNeighbor"`
}

type bgpNeighborItem struct {
	IPAddress string `xml:"IPAddress"`
	RemoteAS  int    `xml:"RemoteAS"`
	LocalAS   int    `xml:"LocalAS"`
	Status    string `xml:"Status"`
}

// ---- OSPF ----

type ospfNeighborResp struct {
	XMLName   xml.Name           `xml:"Response"`
	Neighbors []ospfNeighborItem `xml:"OSPFNeighbor"`
}

type ospfNeighborItem struct {
	RouterID  string `xml:"RouterID"`
	Area      string `xml:"Area"`
	State     string `xml:"State"`
	Interface string `xml:"Interface"`
}
