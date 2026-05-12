package active

import (
	"context"
	"testing"

	"github.com/itom-mini/collector/internal/cidrguard"
	"github.com/itom-mini/collector/internal/wsproto"
)

type quietLog struct{}

func (quietLog) Info(string, ...any)  {}
func (quietLog) Warn(string, ...any)  {}
func (quietLog) Error(string, ...any) {}

func TestExpandTargets_RespectsAllowlist(t *testing.T) {
	guard, _ := cidrguard.New([]string{"10.0.0.0/24"})
	s := &Scanner{Log: quietLog{}, Guard: guard, Emit: func([]wsproto.Observation) error { return nil }}

	state := newRunState(s.Log, guard, s.Emit, withDefaults(Config{}))
	got := s.expandTargets([]string{"10.0.0.0/30", "192.168.1.0/30"}, state)

	// /30 = 4 IPs each, 8 total considered.
	if state.stats.IPsConsidered != 8 {
		t.Errorf("considered = %d; want 8", state.stats.IPsConsidered)
	}
	// Only the four 10.0.0.x IPs pass the allowlist.
	if state.stats.IPsRefusedByCIDR != 4 {
		t.Errorf("refusedByCidr = %d; want 4", state.stats.IPsRefusedByCIDR)
	}
	if len(got) != 4 {
		t.Errorf("returned ips = %d; want 4", len(got))
	}
	for _, ip := range got {
		if !guard.AllowString(ip) {
			t.Errorf("returned ip %s should be in allowlist", ip)
		}
	}
}

func TestSubnetOf_GroupsBy24(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"10.0.5.42", "10.0.5.0/24"},
		{"10.0.5.0", "10.0.5.0/24"},
		{"10.0.5.255", "10.0.5.0/24"},
		{"192.168.1.100", "192.168.1.0/24"},
	}
	for _, tt := range tests {
		got := subnetOf(tt.ip)
		if got != tt.want {
			t.Errorf("subnetOf(%s) = %s; want %s", tt.ip, got, tt.want)
		}
	}
}

func TestVendorFromSysObjectID(t *testing.T) {
	cases := map[string]string{
		"1.3.6.1.4.1.9.1.2370":     "cisco",
		".1.3.6.1.4.1.9.1.2370":    "cisco",
		"1.3.6.1.4.1.12356.101.1": "fortinet",
		"1.3.6.1.4.1.25461.2":     "paloalto",
		"1.3.6.1.4.1.2620.1":      "checkpoint",
		"1.3.6.1.4.1.2636.1.1.1.2.1": "juniper",
		"1.3.6.1.4.1.unknown":     "",
	}
	for in, want := range cases {
		got := vendorFromSysObjectID(in)
		if got != want {
			t.Errorf("vendorFromSysObjectID(%s) = %q; want %q", in, got, want)
		}
	}
}

func TestExtractHeader_CaseInsensitive(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html>"
	if got := extractHeader(resp, "Server"); got != "nginx/1.18.0" {
		t.Errorf("Server = %q", got)
	}
	if got := extractHeader(resp, "server"); got != "nginx/1.18.0" {
		t.Errorf("lowercase server = %q", got)
	}
	if got := extractHeader(resp, "Missing"); got != "" {
		t.Errorf("missing header should return empty, got %q", got)
	}
}

func TestClassifyBytes_DetectsCommonProtocols(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_8.4\r\n":          "ssh",
		"HTTP/1.1 200 OK":                  "http",
		"220 (vsFTPd 3.0.3)\r\n":           "ftp",
		"220 mail.example.com ESMTP Postfix": "smtp",
		"+OK POP3 ready":                   "pop3",
		"* OK IMAP4rev1 service ready":     "imap",
		"random garbage":                   "unknown",
	}
	for in, want := range cases {
		got := classifyBytes([]byte(in))
		if got != want {
			t.Errorf("classifyBytes(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestRateLimiter_PerSubnetIsolated(t *testing.T) {
	r := newRateLimiter(100)
	// Two different /24s — each gets its own bucket.
	r.take("10.0.0.1")
	r.take("10.0.1.1")
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bys) != 2 {
		t.Errorf("expected 2 buckets, got %d", len(r.bys))
	}
}

func TestBuildDNSQuery_Wellformed(t *testing.T) {
	q := buildDNSQuery("_services._dns-sd._udp.local", 12)
	if len(q) < 12+1+4 {
		t.Fatalf("query too short: %d bytes", len(q))
	}
	// Header check: ID=0001, qdcount=1.
	if q[4] != 0 || q[5] != 1 {
		t.Errorf("qdcount = %d.%d; want 0.1", q[4], q[5])
	}
}

func TestBuildNBSTAT_IsTheWildcardQuery(t *testing.T) {
	b := buildNBSTAT()
	// 12 header + 1 length + 32 encoded + 1 null + 4 qtail = 50.
	if len(b) != 50 {
		t.Errorf("nbstat query length = %d; want 50", len(b))
	}
	// QTYPE NBSTAT = 0x0021 at offset 46.
	if b[46] != 0x00 || b[47] != 0x21 {
		t.Errorf("qtype = %02x%02x; want 0021", b[46], b[47])
	}
}

func TestPingTCP_ReturnsFalseOnUnreachable(t *testing.T) {
	// TEST-NET-1 (RFC5737) is reserved unrouted; nothing answers.
	ok, _ := pingTCP(context.Background(), "192.0.2.1", 443, 50_000_000) // 50ms
	if ok {
		t.Error("expected pingTCP to 192.0.2.1 to fail")
	}
}
