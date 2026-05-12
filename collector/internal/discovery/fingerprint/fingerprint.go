// Package fingerprint identifies an unknown device by probing it
// cheaply and reading any identity clues it volunteers. The output is
// a device.Fingerprint — vendor + confidence + the raw evidence.
//
// Probe ladder, cheapest to most invasive:
//
//	1. TCP port shape (a few SYN scans).
//	2. TLS leaf certificate on 443 (subject + issuer almost always leak
//	   vendor name for self-signed appliances).
//	3. SSH banner on 22 (vendor strings are extremely common).
//	4. HTTP `Server:` header on / (medium-strength signal).
//	5. SNMP sysObjectID (authoritative; needs community — wired up in
//	   Chapter 2 once we add a gosnmp dependency).
//
// We collect ALL probes that succeed, score every signal we got, and
// return the highest-scoring vendor. A probe that fails is just
// missing evidence — it never moves the score in the wrong direction.
//
// The package is deliberately stateless: every Identify() call is
// independent and safe to run from many goroutines. The crawl loop
// caps concurrency at a sane number to keep customer gear from getting
// hammered.
package fingerprint

import (
	"context"
	"sync"
	"time"

	"github.com/itom-mini/collector/internal/discovery/device"
)

// Identify runs the probe ladder against host and returns a
// Fingerprint. Probes run with the supplied timeout each — a hung
// firewall (rare but not unheard-of) never stalls the entire crawl.
//
// The function is best-effort: any single probe failing returns an
// empty result for that probe rather than an error. Identify only
// returns an error if ctx is cancelled.
func Identify(ctx context.Context, host string, creds device.Creds, opts Options) (device.Fingerprint, error) {
	if opts.PerProbeTimeout <= 0 {
		opts.PerProbeTimeout = 4 * time.Second
	}
	if opts.PortsToScan == nil {
		// A short, hand-picked list. Network gear nearly always has at
		// least one of these open; an empty result strongly suggests
		// "this isn't reachable management plane" and the crawl can
		// move on without further probing.
		opts.PortsToScan = []int{22, 80, 161 /*UDP, not scanned via TCP*/, 443, 830, 8443}
	}

	fp := device.Fingerprint{}

	// 1. Port shape. Sequential not parallel — a single device, a few
	// ports, total < 1s. Parallel here saves no real time and risks
	// IDS-style "port scan" alerts on the customer's edge.
	ports := scanTCPPorts(ctx, host, opts.PortsToScan, opts.PerProbeTimeout)
	fp.OpenTCPPorts = ports

	// 2-4. Independent probes run in parallel — each one targets a
	// different port so there's no head-of-line blocking.
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		tlsSubj  string
		tlsIss   string
		httpSrv  string
		sshBan   string
	)
	openSet := toSet(ports)

	probe := func(do func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			do()
		}()
	}
	if openSet[443] || openSet[8443] {
		probe(func() {
			port := 443
			if !openSet[443] && openSet[8443] {
				port = 8443
			}
			s, i := probeTLS(ctx, host, port, opts.PerProbeTimeout)
			mu.Lock()
			tlsSubj, tlsIss = s, i
			mu.Unlock()
		})
		probe(func() {
			port := 443
			if !openSet[443] && openSet[8443] {
				port = 8443
			}
			s := probeHTTPServer(ctx, host, port, opts.PerProbeTimeout)
			mu.Lock()
			httpSrv = s
			mu.Unlock()
		})
	}
	if openSet[22] {
		probe(func() {
			b := probeSSHBanner(ctx, host, opts.PerProbeTimeout)
			mu.Lock()
			sshBan = b
			mu.Unlock()
		})
	}
	wg.Wait()

	fp.TLSSubject = tlsSubj
	fp.TLSIssuer = tlsIss
	fp.HTTPServer = httpSrv
	fp.SSHBanner = sshBan
	// 5. SNMP sysObjectID — runs only if SNMP credentials (v2c or v3)
	// were supplied. Authoritative signal when it lands.
	fp.SysObjectID = probeSNMPSysObjectID(ctx, host, creds, opts.PerProbeTimeout)

	fp.Vendor, fp.Confidence, fp.Reasons = score(fp)
	return fp, ctx.Err()
}

// Options tunes the probe behaviour. Zero values are fine for normal
// use; callers (mainly the crawl loop) pass overrides for testing.
type Options struct {
	PerProbeTimeout time.Duration
	PortsToScan     []int
}

func toSet(xs []int) map[int]bool {
	m := make(map[int]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
