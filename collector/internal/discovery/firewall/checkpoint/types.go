package checkpoint

// loginResp is the body of POST /web_api/login.
type loginResp struct {
	Sid              string `json:"sid"`
	Uid              string `json:"uid"`
	URL              string `json:"url"`
	SessionTimeoutS  int    `json:"session-timeout"`
	LastLoginRolesAt string `json:"last-login-was-at"`
}

// ---- gateway list / detail ----

type gatewaysResp struct {
	Objects []gatewayItem `json:"objects"`
	From    int           `json:"from"`
	To      int           `json:"to"`
	Total   int           `json:"total"`
}

type gatewayItem struct {
	Name       string            `json:"name"`
	UID        string            `json:"uid"`
	IPv4       string            `json:"ipv4-address"`
	Version    string            `json:"version"`
	OSName     string            `json:"os-name"`
	Interfaces []gatewayInterface `json:"interfaces"`
}

type gatewayInterface struct {
	Name           string `json:"name"`
	IPv4Address    string `json:"ipv4-address"`
	IPv4MaskLength string `json:"ipv4-mask-length"`
	SecurityZone   string `json:"security-zone"`
	Topology       string `json:"topology"`
}

// ---- NAT rulebase ----

type natRulebaseResp struct {
	Rulebase []natRuleItem `json:"rulebase"`
	Total    int           `json:"total"`
}

type natRuleItem struct {
	Name                  string `json:"name"`
	RuleNumber            int    `json:"rule-number"`
	OriginalSource        string `json:"original-source"`
	OriginalDestination   string `json:"original-destination"`
	OriginalService       string `json:"original-service"`
	TranslatedSource      string `json:"translated-source"`
	TranslatedDestination string `json:"translated-destination"`
	TranslatedService     string `json:"translated-service"`
}

// ---- access rulebase ----

type accessRulebaseResp struct {
	Rulebase []accessRuleItem `json:"rulebase"`
	Total    int              `json:"total"`
}

type accessRuleItem struct {
	Name        string   `json:"name"`
	RuleNumber  int      `json:"rule-number"`
	Source      []string `json:"source"`
	Destination []string `json:"destination"`
	Service     []string `json:"service"`
	Action      string   `json:"action"`
	Enabled     bool     `json:"enabled"`
}

// ---- security zones ----

type zonesResp struct {
	Objects []zoneItem `json:"objects"`
}

type zoneItem struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// ---- VPN communities ----

type communitiesResp struct {
	Objects []communityItem `json:"objects"`
}

type communityItem struct {
	Name           string            `json:"name"`
	UID            string            `json:"uid"`
	Encryption     string            `json:"encryption-method"`
	GatewayMembers []communityMember `json:"gateways"`
}

type communityMember struct {
	Name        string `json:"name"`
	IPv4Address string `json:"ipv4-address"`
}
