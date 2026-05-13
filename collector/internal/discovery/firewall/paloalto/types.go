package paloalto

import "encoding/xml"

// responseEnvelope is the outer wrapper every PAN-OS XML API reply uses.
// We unmarshal envelope first, check `status`, then unmarshal the
// raw `<result>` payload into a vendor-specific struct.
type responseEnvelope struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Result  []byte   `xml:",innerxml"`
}

// keygenResp is the body of /api/?type=keygen — a separate top-level
// shape that does NOT use the response envelope wrapping.
type keygenResp struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Key     string   `xml:"result>key"`
}

// ---- system info ----

type systemInfoResp struct {
	System struct {
		Hostname string `xml:"hostname"`
		Model    string `xml:"model"`
		Serial   string `xml:"serial"`
		SWVer    string `xml:"sw-version"`
	} `xml:"system"`
}

// ---- vsys list ----

type vsysListResp struct {
	Multi string `xml:"cfg.general.multi-vsys"`
}

type multiVsysResp struct {
	Entries []struct {
		Name string `xml:"name,attr"`
	} `xml:"entry"`
}

// ---- interfaces ----

type interfaceAllResp struct {
	HW struct {
		Entries []struct {
			Name  string `xml:"name"`
			State string `xml:"state"`
			MAC   string `xml:"mac"`
		} `xml:"entry"`
	} `xml:"hw"`
	Ifnet struct {
		Entries []struct {
			Name string `xml:"name"`
			IP   string `xml:"ip"`
			Zone string `xml:"zone"`
			Tag  int    `xml:"tag"`
		} `xml:"entry"`
	} `xml:"ifnet"`
}

// ---- routes ----

type routeResp struct {
	Entries []struct {
		VirtualRouter string `xml:"virtual-router"`
		Destination   string `xml:"destination"`
		NextHop       string `xml:"nexthop"`
		Interface     string `xml:"interface"`
		Flags         string `xml:"flags"`
		Metric        int    `xml:"metric"`
	} `xml:"entry"`
}

// ---- ARP ----

type arpResp struct {
	Entries []struct {
		IP        string `xml:"ip"`
		MAC       string `xml:"mac"`
		Interface string `xml:"interface"`
	} `xml:"entries>entry"`
}

// ---- NAT policy ----

type natPolicyResp struct {
	Entries []struct {
		Name        string   `xml:"name,attr"`
		Source      []string `xml:"source>member"`
		Destination []string `xml:"destination>member"`
		Service     []string `xml:"service>member"`
		SourceTranslation struct {
			TranslatedAddress string `xml:"dynamic-ip-and-port>translated-address>member"`
		} `xml:"source-translation"`
		DestinationTranslation struct {
			TranslatedAddress string `xml:"translated-address"`
			TranslatedPort    string `xml:"translated-port"`
		} `xml:"destination-translation"`
	} `xml:"rules>entry"`
}

// ---- zones ----

type zoneResp struct {
	Entries []struct {
		Name    string `xml:"name,attr"`
		Network struct {
			Layer3   []string `xml:"layer3>member"`
			Layer2   []string `xml:"layer2>member"`
			Tap      []string `xml:"tap>member"`
			External []string `xml:"external>member"`
		} `xml:"network"`
	} `xml:"zone>entry"`
}

// ---- security policies ----

type securityPolicyResp struct {
	Entries []struct {
		Name        string   `xml:"name,attr"`
		From        []string `xml:"from>member"`
		To          []string `xml:"to>member"`
		Source      []string `xml:"source>member"`
		Destination []string `xml:"destination>member"`
		Service     []string `xml:"service>member"`
		Action      string   `xml:"action"`
		Disabled    string   `xml:"disabled"`
	} `xml:"rules>entry"`
}

// ---- IPsec SAs ----

type ipsecSAResp struct {
	Entries []struct {
		TunnelName   string `xml:"tnn"`
		GatewayIP    string `xml:"gwip"`
		LocalIPAddr  string `xml:"local-ip"`
		RemoteIPAddr string `xml:"peer-ip"`
	} `xml:"entries>entry"`
}

// ---- BGP peers ----

type bgpPeerResp struct {
	Entries []struct {
		PeerAddress string `xml:"peer-address"`
		LocalAS     int    `xml:"local-as"`
		RemoteAS    int    `xml:"remote-as"`
		Status      string `xml:"status"`
		UptimeSec   int64  `xml:"status-duration"`
	} `xml:"entry"`
}

// ---- OSPF neighbours ----

type ospfNbrResp struct {
	Entries []struct {
		RouterID  string `xml:"neighbor-router-id"`
		Area      string `xml:"area-id"`
		Status    string `xml:"status"`
		Interface string `xml:"neighbor-interface"`
	} `xml:"entry"`
}
