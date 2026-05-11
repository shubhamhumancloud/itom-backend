package crawl

import (
	"context"
	"testing"

	"github.com/itom-mini/collector/internal/cidrguard"
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/driver"
	"github.com/itom-mini/collector/internal/wsproto"
)

// quietLog satisfies the Logger interface without emitting noise during tests.
type quietLog struct{}

func (quietLog) Info(string, ...any)  {}
func (quietLog) Warn(string, ...any)  {}
func (quietLog) Error(string, ...any) {}

// fakeDriver is a programmable Driver used to drive the crawl loop in
// tests. The router map says "if you ingest this IP, you get back these
// neighbours" — letting us simulate "firewall behind a firewall" or a
// fan-out tree without spinning up actual network gear.
type fakeDriver struct {
	v        device.Vendor
	router   map[string][]device.NeighbourHint
	produces map[string][]wsproto.Observation
}

func (f *fakeDriver) Vendor() device.Vendor { return f.v }
func (f *fakeDriver) Ingest(_ context.Context, c device.Creds) (device.IngestResult, error) {
	return device.IngestResult{
		Observations: f.produces[c.Host],
		Neighbours:   f.router[c.Host],
	}, nil
}

// We can't use real fingerprint.Identify in tests (it would actually
// open TCP sockets). To exercise the loop, we register a "fake-known"
// vendor under a sentinel; the test runs assert that crawl handles
// the case where every device fingerprints as VendorUnknown — neighbour
// expansion does NOT happen for unknown devices, so we rely on a
// vendor-hint shortcut: a NeighbourHint's VendorHint field lets the
// caller pre-classify, which the crawl loop honors when the
// fingerprint confidence is not high.
//
// For tests we leverage the same field: every hint carries a
// VendorHint, and the test driver registers under that vendor. Since
// real fingerprinting against 192.0.2.x (TEST-NET-1, unrouted) returns
// ConfidenceNone, the hint kicks in and the driver runs.
//
// This is a true end-to-end exercise of the crawl orchestration code.

func TestCrawl_RespectsDepthCap(t *testing.T) {
	reg := driver.New()
	fd := &fakeDriver{
		v: device.VendorGenericSNMP,
		router: map[string][]device.NeighbourHint{
			"192.0.2.1": {{IP: "192.0.2.2", Reason: "bgp_peer", VendorHint: device.VendorGenericSNMP}},
			"192.0.2.2": {{IP: "192.0.2.3", Reason: "bgp_peer", VendorHint: device.VendorGenericSNMP}},
			"192.0.2.3": {{IP: "192.0.2.4", Reason: "bgp_peer", VendorHint: device.VendorGenericSNMP}},
		},
		produces: map[string][]wsproto.Observation{
			"192.0.2.1": {{SubjectKind: "device", SubjectKey: "ip:192.0.2.1", Attribute: "x", Value: nil}},
			"192.0.2.2": {{SubjectKind: "device", SubjectKey: "ip:192.0.2.2", Attribute: "x", Value: nil}},
			"192.0.2.3": {{SubjectKind: "device", SubjectKey: "ip:192.0.2.3", Attribute: "x", Value: nil}},
		},
	}
	reg.MustRegister(device.VendorGenericSNMP, func() device.Driver { return fd })

	guard, _ := cidrguard.New([]string{"192.0.2.0/24"})
	c := &Crawler{Registry: reg, Guard: guard, Log: quietLog{}}

	var emitted []wsproto.Observation
	emit := func(o []wsproto.Observation) error { emitted = append(emitted, o...); return nil }
	seeds := []Seed{{IP: "192.0.2.1", VendorHint: device.VendorGenericSNMP}}
	_, stats, err := c.Run(context.Background(), seeds, device.Creds{},
		Options{MaxDepth: 1, FingerprintOpts: fingerprintOpts()}, emit)
	if err != nil {
		t.Fatal(err)
	}
	// Depth 0: seed (192.0.2.1) visited.
	// Depth 1: 192.0.2.2 visited.
	// Depth 2 (192.0.2.3) MUST NOT be visited because MaxDepth=1.
	if stats.DevicesVisited != 2 {
		t.Errorf("devices visited = %d; want 2 (seed + 1 hop)", stats.DevicesVisited)
	}
	if stats.Hops != 1 {
		t.Errorf("max hops = %d; want 1", stats.Hops)
	}
}

func TestCrawl_RefusesOutOfCIDRTargets(t *testing.T) {
	reg := driver.New()
	fd := &fakeDriver{
		v: device.VendorGenericSNMP,
		// Hand back a hint that's outside the allowlist.
		router: map[string][]device.NeighbourHint{
			"10.0.0.1": {{IP: "8.8.8.8", Reason: "vpn_peer", VendorHint: device.VendorGenericSNMP}},
		},
		produces: map[string][]wsproto.Observation{
			"10.0.0.1": {{SubjectKind: "device", SubjectKey: "ip:10.0.0.1", Attribute: "ok", Value: nil}},
		},
	}
	reg.MustRegister(device.VendorGenericSNMP, func() device.Driver { return fd })

	guard, _ := cidrguard.New([]string{"10.0.0.0/8"})
	c := &Crawler{Registry: reg, Guard: guard, Log: quietLog{}}

	var refusedFound bool
	emit := func(o []wsproto.Observation) error {
		for _, ob := range o {
			if ob.Attribute == "refused" {
				refusedFound = true
			}
		}
		return nil
	}
	seeds := []Seed{{IP: "10.0.0.1", VendorHint: device.VendorGenericSNMP}}
	_, stats, err := c.Run(context.Background(), seeds, device.Creds{},
		Options{MaxDepth: 2, FingerprintOpts: fingerprintOpts()}, emit)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DevicesRefusedByCIDR != 1 {
		t.Errorf("refused by cidr = %d; want 1 (8.8.8.8 should be refused)", stats.DevicesRefusedByCIDR)
	}
	if !refusedFound {
		t.Error("expected a refused observation in the emitted stream")
	}
}

func TestCrawl_NoDriverEmitsFingerprintOnly(t *testing.T) {
	reg := driver.New() // empty registry
	guard, _ := cidrguard.New([]string{"10.0.0.0/8"})
	c := &Crawler{Registry: reg, Guard: guard, Log: quietLog{}}

	var emitted []wsproto.Observation
	emit := func(o []wsproto.Observation) error { emitted = append(emitted, o...); return nil }
	seeds := []Seed{{IP: "10.0.0.1"}} // no hint — must rely on fingerprint
	_, stats, err := c.Run(context.Background(), seeds, device.Creds{},
		Options{MaxDepth: 1, FingerprintOpts: fingerprintOpts()}, emit)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DevicesUnknown != 1 {
		t.Errorf("unknown = %d; want 1", stats.DevicesUnknown)
	}
	if stats.DevicesIdentified != 0 {
		t.Errorf("identified = %d; want 0", stats.DevicesIdentified)
	}
	// At least the fingerprint observation should have been emitted.
	hasFingerprint := false
	for _, o := range emitted {
		if o.Attribute == "fingerprint" {
			hasFingerprint = true
		}
	}
	if !hasFingerprint {
		t.Error("expected a fingerprint observation even with no driver")
	}
}
