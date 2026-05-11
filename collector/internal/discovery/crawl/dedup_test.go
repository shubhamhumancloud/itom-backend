package crawl

import (
	"context"
	"sync"
	"testing"

	"github.com/itom-mini/collector/internal/cidrguard"
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/driver"
	"github.com/itom-mini/collector/internal/wsproto"
)

// chassisDriver returns the same chassis ID for every IP it's asked
// to ingest — simulating a router with multiple management IPs.
type chassisDriver struct {
	chassisID string
	mu        sync.Mutex
	calls     []string
}

func (c *chassisDriver) Vendor() device.Vendor { return device.VendorGenericSNMP }
func (c *chassisDriver) Ingest(_ context.Context, creds device.Creds) (device.IngestResult, error) {
	c.mu.Lock()
	c.calls = append(c.calls, creds.Host)
	c.mu.Unlock()
	return device.IngestResult{
		ChassisID: c.chassisID,
		Observations: []wsproto.Observation{{
			SubjectKind: "device",
			SubjectKey:  "chassis:" + c.chassisID,
			Attribute:   "fake",
			Value:       map[string]any{"host": creds.Host},
		}},
	}, nil
}

func TestCrawl_DedupsByChassisID(t *testing.T) {
	cd := &chassisDriver{chassisID: "FOC2401X1ABC"}
	reg := driver.New()
	reg.MustRegister(device.VendorGenericSNMP, func() device.Driver { return cd })

	guard, _ := cidrguard.New([]string{"10.0.0.0/24"})

	var emitted []wsproto.Observation
	emit := func(o []wsproto.Observation) error {
		emitted = append(emitted, o...)
		return nil
	}

	c := &Crawler{Registry: reg, Guard: guard, Log: quietLog{}}
	seeds := []Seed{
		{IP: "10.0.0.1", VendorHint: device.VendorGenericSNMP},
		{IP: "10.0.0.2", VendorHint: device.VendorGenericSNMP},
		{IP: "10.0.0.3", VendorHint: device.VendorGenericSNMP},
	}
	// MaxConcurrency=1 makes this deterministic — the first seed wins
	// the chassis row, the other two emit alias rows.
	_, stats, err := c.Run(context.Background(), seeds, device.Creds{},
		Options{MaxDepth: 0, MaxConcurrency: 1, FingerprintOpts: fingerprintOpts()}, emit)
	if err != nil {
		t.Fatal(err)
	}

	// All three IPs visited.
	if stats.DevicesVisited != 3 {
		t.Errorf("DevicesVisited = %d, want 3", stats.DevicesVisited)
	}
	// Only the first one counted as "identified" — the rest are aliases.
	if stats.DevicesIdentified != 1 {
		t.Errorf("DevicesIdentified = %d, want 1 (others are aliases)", stats.DevicesIdentified)
	}
	if stats.ChassisAliases != 2 {
		t.Errorf("ChassisAliases = %d, want 2", stats.ChassisAliases)
	}

	// Two chassis_alias observations should be emitted.
	aliasCount := 0
	for _, o := range emitted {
		if o.SubjectKind == "chassis_alias" {
			aliasCount++
		}
	}
	if aliasCount != 2 {
		t.Errorf("chassis_alias observations = %d, want 2", aliasCount)
	}
}

func TestCrawl_AuthFailureClassified(t *testing.T) {
	failing := &errDriver{err: &device.ErrAuth{Wrapped: nil}}
	reg := driver.New()
	reg.MustRegister(device.VendorGenericSNMP, func() device.Driver { return failing })

	guard, _ := cidrguard.New([]string{"10.0.0.0/24"})
	c := &Crawler{Registry: reg, Guard: guard, Log: quietLog{}}

	var emitted []wsproto.Observation
	_, stats, _ := c.Run(context.Background(),
		[]Seed{{IP: "10.0.0.1", VendorHint: device.VendorGenericSNMP}},
		device.Creds{},
		Options{MaxDepth: 0, MaxConcurrency: 1, FingerprintOpts: fingerprintOpts()},
		func(o []wsproto.Observation) error { emitted = append(emitted, o...); return nil })

	if stats.DevicesAuthFailed != 1 {
		t.Errorf("DevicesAuthFailed = %d, want 1", stats.DevicesAuthFailed)
	}
	if stats.DevicesUnreachable != 0 {
		t.Errorf("DevicesUnreachable = %d, want 0", stats.DevicesUnreachable)
	}
	// And the observation should carry the structured reason.
	found := false
	for _, o := range emitted {
		if o.Attribute == "auth_failed" {
			found = true
		}
	}
	if !found {
		t.Error("expected an auth_failed observation")
	}
}

type errDriver struct{ err error }

func (e *errDriver) Vendor() device.Vendor { return device.VendorGenericSNMP }
func (e *errDriver) Ingest(context.Context, device.Creds) (device.IngestResult, error) {
	return device.IngestResult{}, e.err
}
