package wsclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/itom-mini/collector/internal/cidrguard"
	"github.com/itom-mini/collector/internal/discovery/crawl"
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/driver"
	"github.com/itom-mini/collector/internal/discovery/drivers/generic_snmp"
	"github.com/itom-mini/collector/internal/discovery/firewall/fortigate"
	"github.com/itom-mini/collector/internal/wsproto"
)

// CredentialResolver hands the dispatcher decrypted credentials JIT.
// In production this is a thin HTTP client against the BE's
// /v1/discovery/credentials/:id/decrypt endpoint. The dispatcher zeroes
// the strings it gets back as soon as the run ends — they only live
// in RAM for the duration of one job.
type CredentialResolver interface {
	Resolve(ctx context.Context, tenantID, credentialID string) (device.Creds, error)
}

// Dispatcher implements wsclient.Handler. It owns:
//   - signature verification of the CIDR allowlist
//   - building the per-job crawl
//   - chunking observations into ScanJobChunk frames
type Dispatcher struct {
	log           Logger
	cidrPublicKey ed25519.PublicKey
	creds         CredentialResolver
	registry      *driver.Registry
	chunkSize     int
}

// DispatcherConfig holds the dispatcher's wiring.
type DispatcherConfig struct {
	Logger Logger
	// CIDRPublicKey is the BE's Ed25519 public key, base64-encoded as the
	// collectord receives it via baked-var / config. Empty means the
	// dispatcher refuses every job — fail closed, not open.
	CIDRPublicKeyBase64 string
	Credentials         CredentialResolver
	// ChunkSize caps observations per ScanJobChunk frame. The agent has
	// a 256 KiB ceiling per frame; 200 observation rows of ~500 bytes
	// stays well below that.
	ChunkSize int
}

// NewDispatcher returns a configured Dispatcher with the default driver
// registry pre-populated (FortiGate today; Palo Alto / Check Point /
// Cisco / generic-SNMP land in later chapters).
func NewDispatcher(cfg DispatcherConfig) (*Dispatcher, error) {
	if cfg.Logger == nil {
		return nil, errors.New("dispatcher: Logger is required")
	}
	if cfg.Credentials == nil {
		return nil, errors.New("dispatcher: CredentialResolver is required")
	}
	if cfg.CIDRPublicKeyBase64 == "" {
		return nil, errors.New("dispatcher: CIDRPublicKeyBase64 is required (refusing to fail-open)")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.CIDRPublicKeyBase64))
	if err != nil {
		return nil, fmt.Errorf("dispatcher: cidr public key not base64: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"dispatcher: cidr public key wrong length: got %d, want %d",
			len(keyBytes), ed25519.PublicKeySize,
		)
	}
	chunk := cfg.ChunkSize
	if chunk <= 0 {
		chunk = 200
	}

	reg := driver.New()
	reg.MustRegister(device.VendorFortiGate, fortigate.Factory)
	reg.MustRegister(device.VendorGenericSNMP, generic_snmp.Factory)
	// Cisco IOS — currently routed through generic_snmp; will get its
	// own driver when we add the per-VLAN community trick.
	reg.MustRegister(device.VendorCiscoIOS, generic_snmp.Factory)
	// Future chapters plug in here:
	//   reg.MustRegister(device.VendorPaloAlto, paloalto.Factory)

	return &Dispatcher{
		log:           cfg.Logger,
		cidrPublicKey: ed25519.PublicKey(keyBytes),
		creds:         cfg.Credentials,
		registry:      reg,
		chunkSize:     chunk,
	}, nil
}

// Run satisfies wsclient.Handler.
func (d *Dispatcher) Run(
	ctx context.Context,
	a wsproto.ScanJobAssign,
	emit func(wsproto.ScanJobChunk) error,
) (int, error) {
	// 1. Verify the CIDR allowlist signature. A failure here means
	// either the BE has a bug or someone is impersonating the BE; in
	// both cases we refuse and let the audit_log row carry the why.
	guard, err := cidrguard.VerifyAndLoad(d.cidrPublicKey, a.AllowlistCIDRs, a.AllowlistSignature)
	if err != nil {
		return 0, err
	}
	d.log.Info(
		"scan job picked up",
		"jobId", a.JobID, "pillar", a.Pillar, "vendor", a.Vendor,
		"cidrs", guard.CIDRs(),
	)

	switch a.Pillar {
	case "firewall":
		// Chapter-1 pillar name is kept for backward compat, but it
		// now drives the full seed-and-crawl loop — operators don't
		// have to declare a single firewall up front anymore.
		return d.runCrawl(ctx, a, guard, emit)
	case "noop":
		obs := []wsproto.Observation{{
			SubjectKind: "sentinel",
			SubjectKey:  "noop",
			Attribute:   "echo",
			Value:       map[string]any{"jobId": a.JobID},
			SeenAt:      time.Now().UTC().Format(time.RFC3339Nano),
		}}
		if err := emit(wsproto.ScanJobChunk{Observations: obs}); err != nil {
			return 0, err
		}
		return 1, nil
	default:
		return 0, fmt.Errorf("pillar %q not implemented (SNMP/active land in chapters 2-3)", a.Pillar)
	}
}

// runCrawl drives the seed-and-walk loop. Seeds come from the
// ScanJobAssign target spec; if missing, we fall back to the
// credential's host (legacy single-firewall mode), which keeps every
// pre-crawl scan-job row functional.
func (d *Dispatcher) runCrawl(
	ctx context.Context,
	a wsproto.ScanJobAssign,
	guard *cidrguard.Guard,
	emit func(wsproto.ScanJobChunk) error,
) (int, error) {
	if len(a.CredentialIDs) == 0 {
		return 0, errors.New("crawl job has no credentials")
	}
	creds, err := d.creds.Resolve(ctx, a.TenantID, a.CredentialIDs[0])
	if err != nil {
		return 0, fmt.Errorf("resolve credential: %w", err)
	}

	// Seeds: prefer explicit list from targetSpec; fall back to the
	// credential's host. Both shapes valid; the latter keeps
	// chapter-0/1 jobs working without re-issuing them. If the job
	// carries a vendor field, we treat every seed as that vendor
	// (operator-declared mode); otherwise the crawl fingerprints.
	hint := device.Vendor(a.Vendor)
	seeds := readSeeds(a.TargetSpec, hint)
	if len(seeds) == 0 {
		host := stripScheme(creds.Host)
		if host != "" {
			seeds = []crawl.Seed{{IP: host, VendorHint: hint}}
		}
	}
	if len(seeds) == 0 {
		return 0, errors.New("no seeds: provide targetSpec.seeds or a credential with a host")
	}
	d.log.Info("crawl seeds resolved", "jobId", a.JobID, "seedCount", len(seeds))

	opts := crawl.Options{
		MaxDepth:       readInt(a.TargetSpec, "maxDepth", 3),
		MaxDevices:     readInt(a.TargetSpec, "maxDevices", 256),
		MaxConcurrency: readInt(a.TargetSpec, "maxConcurrency", 8),
	}

	crawler := &crawl.Crawler{
		Registry: d.registry,
		Guard:    guard,
		Log:      d.log,
	}

	emitFn := func(obs []wsproto.Observation) error {
		return emit(wsproto.ScanJobChunk{Observations: obs})
	}
	total, stats, err := crawler.Run(ctx, seeds, creds, opts, emitFn)
	if err != nil {
		return total, err
	}

	// Final summary observation so the operator gets one row that
	// describes the crawl as a whole (devices visited, refused, etc.)
	// instead of having to aggregate over many.
	seedIPs := make([]string, 0, len(seeds))
	for _, s := range seeds {
		seedIPs = append(seedIPs, s.IP)
	}
	summary := wsproto.Observation{
		SubjectKind: "scan_summary",
		SubjectKey:  fmt.Sprintf("job:%s", a.JobID),
		Attribute:   "crawl_stats",
		Value: map[string]any{
			"seeds":             seedIPs,
			"devicesVisited":    stats.DevicesVisited,
			"devicesIdentified": stats.DevicesIdentified,
			"devicesUnknown":    stats.DevicesUnknown,
			"refusedByCidr":     stats.DevicesRefusedByCIDR,
			"driverFailures":    stats.DriverFailures,
			"maxHops":           stats.Hops,
		},
		SeenAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := emit(wsproto.ScanJobChunk{Observations: []wsproto.Observation{summary}}); err != nil {
		return total, err
	}
	return total + 1, nil
}

// readSeeds extracts the seeds list from targetSpec. Supports:
//   - new shape:    seeds: ["10.0.0.1", "10.0.0.2"]
//   - legacy shape: host: "10.0.0.1"
//
// The vendor hint applies to every seed; richer per-seed vendor hints
// can be added later by accepting [{ip, vendor}] objects.
func readSeeds(spec map[string]any, hint device.Vendor) []crawl.Seed {
	if spec == nil {
		return nil
	}
	wrap := func(ips []string) []crawl.Seed {
		out := make([]crawl.Seed, 0, len(ips))
		for _, ip := range ips {
			if ip != "" {
				out = append(out, crawl.Seed{IP: ip, VendorHint: hint})
			}
		}
		return out
	}
	if v, ok := spec["seeds"]; ok {
		switch xs := v.(type) {
		case []any:
			out := make([]string, 0, len(xs))
			for _, x := range xs {
				if s, ok := x.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			return wrap(out)
		case []string:
			return wrap(xs)
		}
	}
	if v, ok := spec["host"]; ok {
		if s, ok := v.(string); ok && s != "" {
			return wrap([]string{s})
		}
	}
	return nil
}

func readInt(spec map[string]any, key string, def int) int {
	if spec == nil {
		return def
	}
	v, ok := spec[key]
	if !ok {
		return def
	}
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		// JSON numbers decode to float64 in map[string]any.
		return int(x)
	default:
		return def
	}
}

func stripScheme(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	s = strings.SplitN(s, "/", 2)[0]
	s = strings.SplitN(s, ":", 2)[0]
	return s
}

