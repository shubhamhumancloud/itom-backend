package cisco_asa

// rangePager is the small interface every paginated response satisfies
// so the generic getAll walker can advance through pages without
// caring about the concrete item type.
type rangePager interface {
	pageLen() int
	totalCount() int
}

// itemsEnvelope is the standard ASA REST collection wrapper.
type itemsEnvelope[T any] struct {
	Kind      string `json:"kind"`
	Items     []T    `json:"items"`
	RangeInfo struct {
		Offset int `json:"offset"`
		Limit  int `json:"limit"`
		Total  int `json:"total"`
	} `json:"rangeInfo"`
}

func (e *itemsEnvelope[T]) pageLen() int    { return len(e.Items) }
func (e *itemsEnvelope[T]) totalCount() int { return e.RangeInfo.Total }

// objectRef is ASA REST's "this is either a literal IPv4 or an object
// reference" union. We surface whichever is populated; the consumer
// decides what to do with object names.
type objectRef struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Name    string `json:"name"`
	RefLink string `json:"refLink"`
}

// ---- device monitor ----

type deviceMonitor struct {
	Hostname   string `json:"hostname"`
	SWVersion  string `json:"version"`
	Serial     string `json:"serialNumber"`
	DeviceType string `json:"deviceType"`
}

// ---- contexts (multi-context mode) ----

type contextItem struct {
	Name string `json:"name"`
}

// ---- interfaces ----

type interfaceItem struct {
	Kind          string `json:"kind"`
	HardwareID    string `json:"hardwareID"`
	Name          string `json:"name"`
	SecurityLevel int    `json:"securityLevel"`
	VLANID        int    `json:"vlanID"`
	LinkStatus    string `json:"linkStatus"`
	Shutdown      bool   `json:"shutdown"`
	MACAddress    string `json:"macAddress"`
	IPAddress     struct {
		Kind    string    `json:"kind"`
		IP      objectRef `json:"ip"`
		Netmask objectRef `json:"netMask"`
	} `json:"ipAddress"`
}

// ---- routes ----

type routeItem struct {
	Network   string `json:"network"`
	Netmask   string `json:"netmask"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
	Protocol  string `json:"protocol"`
	Metric    int    `json:"metric"`
}

type staticRouteItem struct {
	Kind           string    `json:"kind"`
	Interface      objectRef `json:"interface"`
	NetworkObject  objectRef `json:"networkObject"`
	Gateway        objectRef `json:"gateway"`
	Metric         int       `json:"metric"`
	TunneledOption bool      `json:"tunneledOption"`
}

// ---- ARP ----

type arpItem struct {
	IPAddress  string `json:"ipAddress"`
	MACAddress string `json:"macAddress"`
	Interface  string `json:"interface"`
}

// ---- Twice-NAT ----

type twiceNatItem struct {
	Kind                 string    `json:"kind"`
	Position             int       `json:"position"`
	OriginalSource       objectRef `json:"originalSource"`
	OriginalDestination  objectRef `json:"originalDestination"`
	OriginalService      struct {
		Value    string `json:"value"`
		Protocol string `json:"protocol"`
	} `json:"originalService"`
	TranslatedSource      objectRef `json:"translatedSource"`
	TranslatedDestination objectRef `json:"translatedDestination"`
	TranslatedService     struct {
		Value    string `json:"value"`
		Protocol string `json:"protocol"`
	} `json:"translatedService"`
}

// ---- ACL rule ----

type aclRuleItem struct {
	Kind               string    `json:"kind"`
	Position           int       `json:"position"`
	Permit             string    `json:"permit"`
	Active             bool      `json:"active"`
	SourceAddress      objectRef `json:"sourceAddress"`
	DestinationAddress objectRef `json:"destinationAddress"`
	DestinationService objectRef `json:"destinationService"`
}

// ---- VPN ----

type lanVpnItem struct {
	Kind           string   `json:"kind"`
	IPAddress      string   `json:"ipAddress"`
	IKEVersion     string   `json:"ikeVersion"`
	LocalNetworks  []string `json:"localNetworks"`
	RemoteNetworks []string `json:"remoteNetworks"`
}

// ---- BGP / OSPF ----

type bgpNeighborItem struct {
	NeighborAddress string `json:"neighborAddress"`
	RemoteAS        int    `json:"remoteAs"`
	State           string `json:"state"`
	UpTime          int64  `json:"upTime"`
}

type ospfNeighborItem struct {
	NeighborID string `json:"neighborId"`
	Area       string `json:"area"`
	State      string `json:"state"`
	Interface  string `json:"interface"`
}
