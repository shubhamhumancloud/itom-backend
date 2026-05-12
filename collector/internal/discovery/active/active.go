// Package active implements the active scanner — chapter 3. Given a
// list of CIDR ranges, it sends polite probes to every IP and records
// who responds. Output is observations under the existing observation
// model (`host`, `open_port`).
//
// Cross-platform: every probe in this package uses pure-Go stdlib or
// pro-bing's unprivileged mode. The same binary works on Linux,
// macOS, and Windows without admin / CAP_NET_RAW / Npcap. Privileged
// modes (raw ARP, SYN scan) are documented future enhancements.
//
// Five stages (chapter 3 doc):
//
//	1. Discovery — ICMP + TCP-ping to detect aliveness
//	2. Port scan — TCP connect against top ports on alive hosts
//	3. Banner grab — protocol-specific reads for HTTP/SSH/TLS
//	4. SNMP probe — sysObjectID + sysName + sysDescr
//	5. Multicast — one-shot mDNS/NetBIOS/WS-Discovery/SSDP per subnet
//
// Every single packet is gated by:
//   - the signed CIDR allowlist (per-tenant — guards.AllowString),
//   - a per-/24 packet-per-second token bucket (rate cap).
//
// Both are non-negotiable: chapter 3 doc says so explicitly, and
// scanning a customer's network without these rails is how you wake
// up at 3am with their security team on the line.
package active

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/itom-mini/collector/internal/cidrguard"
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/wsproto"
)

// Logger is the slim interface every package in discovery uses.
type Logger interface {
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

// Config tunes one active scan. Sensible defaults applied in Run() if
// zero values come in.
type Config struct {
	// Cidrs is the list of subnets to sweep. Each is expanded to
	// individual IPs; the allowlist is consulted on each IP.
	Cidrs []string

	// Ports to probe in stage 2. Empty falls back to the top-20 list.
	Ports []int

	// MaxConcurrency caps parallel host workers. Chapter 3 doc recommends
	// 500-1000 max; we default to 256 to stay gentle on first runs.
	MaxConcurrency int

	// RateLimitPPS is the per-/24 packet rate cap. Default 1000.
	RateLimitPPS int

	// SNMPCommunities is the ordered list of community strings to try in
	// stage 4. The caller (driver / dispatcher) should put the tenant's
	// configured community first, then "public"/"private" if the tenant
	// opted into default-fallback. We never default to defaults here —
	// must be supplied.
	SNMPCommunities []string

	// HostTimeout caps per-host total work. Beyond this we move on.
	HostTimeout time.Duration

	// SkipMulticast disables stage 5 (handy for environments where
	// IGMP / multicast routing is blocked).
	SkipMulticast bool
}

// Stats summarises one run.
type Stats struct {
	IPsConsidered      int
	IPsRefusedByCIDR   int
	HostsAlive         int
	HostsUnresponsive  int
	OpenPorts          int
	BannersGrabbed     int
	SNMPMatches        int
	MulticastResponses int
}

// Scanner is the per-run orchestrator. It owns the rate limiter, the
// worker pool, and the shared output buffer.
type Scanner struct {
	Log     Logger
	Guard   *cidrguard.Guard
	Creds   device.Creds // tenant creds — community is the first SNMP try

	// Emit is the per-batch observation sink. The scanner flushes
	// every ~200 observations and at end-of-run.
	Emit func([]wsproto.Observation) error
}

// Run executes one active scan against cfg. Returns total observations
// emitted + Stats.
func (s *Scanner) Run(ctx context.Context, cfg Config) (int, Stats, error) {
	if s.Log == nil {
		return 0, Stats{}, fmt.Errorf("active: Logger is required")
	}
	if s.Guard == nil {
		return 0, Stats{}, fmt.Errorf("active: cidrguard.Guard is required (refusing to scan without allowlist)")
	}
	if s.Emit == nil {
		return 0, Stats{}, fmt.Errorf("active: Emit callback is required")
	}
	cfg = withDefaults(cfg)

	state := newRunState(s.Log, s.Guard, s.Emit, cfg)
	defer state.flush()

	// 1. Expand CIDRs to IPs, applying the allowlist as we go. Anything
	// outside the allowlist gets a refused observation and a stat bump.
	targets := s.expandTargets(cfg.Cidrs, state)
	s.Log.Info("active scan: targets resolved",
		"considered", state.stats.IPsConsidered,
		"refused", state.stats.IPsRefusedByCIDR,
		"toScan", len(targets),
	)

	// 2. Run stages 1-4 per-host with bounded concurrency.
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.MaxConcurrency)
	for _, ip := range targets {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			s.scanHost(ctx, ip, cfg, state)
		}(ip)
	}
	wg.Wait()

	// 3. Stage 5 — multicast — once per /24 the scan touched.
	if !cfg.SkipMulticast {
		s.runMulticastForSubnets(ctx, targets, state)
	}

	return state.totalObs, state.stats, nil
}

func withDefaults(c Config) Config {
	if c.MaxConcurrency <= 0 {
		c.MaxConcurrency = 256
	}
	if c.RateLimitPPS <= 0 {
		c.RateLimitPPS = 1000
	}
	if c.HostTimeout <= 0 {
		c.HostTimeout = 30 * time.Second
	}
	if len(c.Ports) == 0 {
		c.Ports = DefaultTopPorts()
	}
	return c
}

// expandTargets walks every CIDR, emits an "out_of_allowlist" observation
// for IPs the guard refuses, and returns only the IPs we'll actually probe.
//
// Memory: a /24 = 256 IPs, a /16 = 65k IPs. We store strings (15 bytes
// avg) so /16 is 1MB — fine. Larger ranges should be chunked by the
// caller; we don't do that here.
func (s *Scanner) expandTargets(cidrs []string, state *runState) []string {
	var out []string
	for _, c := range cidrs {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			s.Log.Warn("active: bad CIDR; skipping", "cidr", c, "err", err)
			continue
		}
		addr := prefix.Masked().Addr()
		for prefix.Contains(addr) {
			ip := addr.String()
			state.stats.IPsConsidered++
			if !s.Guard.AllowString(ip) {
				state.stats.IPsRefusedByCIDR++
				// Don't emit per-IP refusal — a /16 would generate 65k
				// noise rows. Single summary row in dispatcher's
				// summary observation is enough.
			} else {
				out = append(out, ip)
			}
			addr = addr.Next()
			if !addr.IsValid() {
				break
			}
		}
	}
	return out
}

// DefaultTopPorts is the chapter-3 top-20 list. Order matters: stage 2
// probes them in this sequence and stops short if context cancels.
//
// Mix of: web (80/443/8080/8443), remote-admin (22/3389/23), file
// services (445/139/2049), database (3306/5432/1433), telephony (5060/554),
// printing (9100/631), SNMP (161 — UDP, handled separately), Hyper-V/
// vSphere (902), WinRM (5985/5986), Cisco-isms (135).
func DefaultTopPorts() []int {
	return []int{
		22, 80, 443, 445, 3389, 554, 631, 902, 8080, 8443,
		135, 23, 9100, 5060, 1433, 3306, 5432, 5985, 5986, 139,
	}
}
