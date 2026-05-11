package firewall

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMapInterfaces_subjectKeyAndValueShape(t *testing.T) {
	ctx := Context{Name: "root"}
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	got := MapInterfaces(ctx, []Interface{
		{Name: "port1", Zone: "trust", Status: "up", IPs: []string{"10.0.0.1/24"}, MAC: "aa:bb:cc:dd:ee:ff"},
	}, now)
	if len(got) != 1 {
		t.Fatalf("want 1 observation, got %d", len(got))
	}
	obs := got[0]
	if obs.SubjectKind != "interface" {
		t.Errorf("subjectKind = %q", obs.SubjectKind)
	}
	if obs.SubjectKey != "ctx:root|iface:port1" {
		t.Errorf("subjectKey = %q", obs.SubjectKey)
	}
	if obs.SeenAt != "2026-05-11T12:00:00Z" {
		t.Errorf("seenAt = %q", obs.SeenAt)
	}
	// Value must round-trip through JSON (it's marshaled into the WS frame).
	raw, err := json.Marshal(obs.Value)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name":"port1"`, `"zone":"trust"`, `"status":"up"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("value missing %s: %s", want, raw)
		}
	}
}

func TestMapRoutes_includesAllKeyFields(t *testing.T) {
	ctx := Context{Name: "vsys1"}
	got := MapRoutes(ctx, []Route{
		{VirtualRouter: "default", Prefix: "10.20.0.0/16", NextHop: "10.0.0.1", Protocol: "static"},
	}, time.Now())
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].SubjectKey != "ctx:vsys1|route:vr=default,prefix=10.20.0.0/16,nh=10.0.0.1" {
		t.Errorf("subjectKey = %q", got[0].SubjectKey)
	}
}

func TestMapVpnTunnels_carriesProxyIDs(t *testing.T) {
	ctx := Context{Name: "root"}
	got := MapVpnTunnels(ctx, []VpnTunnel{
		{
			Name:          "HQ-Pune",
			PeerIP:        "203.0.113.10",
			LocalSubnets:  []string{"10.0.0.0/16"},
			RemoteSubnets: []string{"10.20.0.0/16"},
			Status:        "up",
		},
	}, time.Now())
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].SubjectKey != "ctx:root|vpn:HQ-Pune" {
		t.Errorf("subjectKey = %q", got[0].SubjectKey)
	}
	raw, _ := json.Marshal(got[0].Value)
	if !strings.Contains(string(raw), `"localSubnets":["10.0.0.0/16"]`) {
		t.Errorf("missing localSubnets: %s", raw)
	}
	if !strings.Contains(string(raw), `"remoteSubnets":["10.20.0.0/16"]`) {
		t.Errorf("missing remoteSubnets: %s", raw)
	}
}
