// Command collectord is the network-discovery collector daemon.
//
// Architectural note: this is intentionally a SEPARATE Go module from the
// host-metrics agent at backend/agent/. The collector runs once per
// customer site (not per host), talks to the same NestJS backend, and has
// a fundamentally different workload profile (bursty SNMP / firewall API
// I/O instead of steady-state local sampling). Keeping the binaries
// separate lets us evolve them independently. If real duplication becomes
// painful later we can extract shared pieces (kardianos wrapper, baked
// vars, paths helper) into a third module.
//
// Status: Chapter 1 — firewall ingest is wired. SNMP (Ch 2) and active
// probing (Ch 3) plug in by adding new pillars to the dispatcher.
//
// CLI surface (provided by kardianos/service):
//
//	itom-collector install      register with the OS service manager
//	itom-collector uninstall    unregister from the OS service manager
//	itom-collector start        ask the service manager to start it
//	itom-collector stop         ask the service manager to stop it
//	itom-collector restart      stop + start
//	itom-collector status       service status
//	itom-collector run          run in the foreground (default when no args)
//	itom-collector version      print version
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/service"

	"github.com/itom-mini/collector/internal/wsclient"
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z"
var Version = "0.1.0"

// Patchable identity, written by the backend's BinaryPatcherService at
// install-request time. Same byte-patching trick as the agent. The patcher
// must be updated to support these placeholders before we ship a real
// collector install endpoint.
var (
	bakedTenantID = "ITOMBAKED_TENANT_ID:" + // 20
		"__________" + "__________" + "__________" + "__________" + "____" // 44 → 64

	bakedServerURL = "ITOMBAKED_SERVER_URL:" + // 21
		"__________" + "__________" + "__________" + "__________" + "__________" + // 50
		"__________" + "__________" + "__________" + "__________" + "__________" + // 100
		"__________" + "__________" + "__________" + "__________" + "__________" + // 150
		"__________" + "__________" + "__________" + "__________" + "__________" + // 200
		"__________" + "__________" + "__________" + "_____" // 235 → 256
)

const (
	tenantIDPrefix  = "ITOMBAKED_TENANT_ID:"
	serverURLPrefix = "ITOMBAKED_SERVER_URL:"
	tenantIDLen     = 64
	serverURLLen    = 256
	bakedPadCutset  = "_\x00"
)

func init() {
	if len(bakedTenantID) != tenantIDLen {
		panic(fmt.Sprintf("bakedTenantID length is %d; want %d", len(bakedTenantID), tenantIDLen))
	}
	if len(bakedServerURL) != serverURLLen {
		panic(fmt.Sprintf("bakedServerURL length is %d; want %d", len(bakedServerURL), serverURLLen))
	}
}

// resolvedIdentity carries everything the WS client + dispatcher need
// to come up. We pull tenantId / serverUrl from baked vars (or env in
// dev) and the rest from env (the patcher will gain placeholders for
// these once we ship a real collector install endpoint).
type resolvedIdentity struct {
	tenantID       string
	serverURL      string
	collectorID    string
	authToken      string
	cidrPubKeyB64  string
}

// resolveIdentity prefers baked values over env vars; env vars are the
// dev fallback. Failing here is fatal — we can't run a job without a
// tenant id, server url, or signature-verification key.
func resolveIdentity() (resolvedIdentity, error) {
	tid := strings.TrimRight(bakedTenantID, bakedPadCutset)
	url := strings.TrimRight(bakedServerURL, bakedPadCutset)
	if strings.HasPrefix(tid, tenantIDPrefix) {
		tid = os.Getenv("ITOM_COLLECTOR_TENANT_ID")
	}
	if strings.HasPrefix(url, serverURLPrefix) {
		url = os.Getenv("ITOM_COLLECTOR_SERVER_URL")
	}
	r := resolvedIdentity{
		tenantID:      tid,
		serverURL:     url,
		collectorID:   os.Getenv("ITOM_COLLECTOR_ID"),
		authToken:     os.Getenv("ITOM_COLLECTOR_AUTH_TOKEN"),
		cidrPubKeyB64: os.Getenv("ITOM_COLLECTOR_CIDR_PUBKEY"),
	}
	if r.tenantID == "" {
		return r, fmt.Errorf("missing tenantId (set baked var or ITOM_COLLECTOR_TENANT_ID)")
	}
	if r.serverURL == "" {
		return r, fmt.Errorf("missing serverUrl (set baked var or ITOM_COLLECTOR_SERVER_URL)")
	}
	if r.collectorID == "" {
		return r, fmt.Errorf("missing collectorId (set ITOM_COLLECTOR_ID)")
	}
	if r.authToken == "" {
		return r, fmt.Errorf("missing auth token (set ITOM_COLLECTOR_AUTH_TOKEN)")
	}
	if r.cidrPubKeyB64 == "" {
		return r, fmt.Errorf("missing cidr public key (set ITOM_COLLECTOR_CIDR_PUBKEY); refusing to run without signature verification")
	}
	return r, nil
}

type program struct {
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

func (p *program) Start(_ service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		runCollector(ctx)
	}()
	return nil
}

func (p *program) Stop(_ service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
	}
	return nil
}

// stderrLogger is the small wsclient.Logger implementation we wire in.
// Keeping it tiny here (rather than pulling in slog or zap) makes the
// collector's startup deterministic and removes a build dependency.
type stderrLogger struct{ l *log.Logger }

func (s *stderrLogger) write(level, msg string, kv []any) {
	parts := make([]string, 0, len(kv)/2+2)
	parts = append(parts, level, msg)
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, fmt.Sprintf("%v=%v", kv[i], kv[i+1]))
	}
	s.l.Println(strings.Join(parts, " "))
}
func (s *stderrLogger) Info(msg string, kv ...any)  { s.write("INFO", msg, kv) }
func (s *stderrLogger) Warn(msg string, kv ...any)  { s.write("WARN", msg, kv) }
func (s *stderrLogger) Error(msg string, kv ...any) { s.write("ERROR", msg, kv) }

// runCollector is the long-running loop. Builds the WS client +
// dispatcher and hands control to wsclient.Run, which owns the
// dial-hello-reconnect state machine.
func runCollector(ctx context.Context) {
	logger := &stderrLogger{l: log.New(os.Stderr, "[collectord] ", log.LstdFlags|log.LUTC)}

	id, err := resolveIdentity()
	if err != nil {
		logger.Error("identity resolution failed", "err", err)
		return
	}
	logger.Info(
		"identity",
		"tenantId", id.tenantID, "serverUrl", id.serverURL, "collectorId", id.collectorID,
	)

	creds := wsclient.NewHTTPCredentialResolver(id.serverURL, id.authToken, id.collectorID, nil)

	dispatcher, err := wsclient.NewDispatcher(wsclient.DispatcherConfig{
		Logger:              logger,
		CIDRPublicKeyBase64: id.cidrPubKeyB64,
		Credentials:         creds,
	})
	if err != nil {
		logger.Error("dispatcher init failed", "err", err)
		return
	}

	client, err := wsclient.New(wsclient.Config{
		ServerURL:   id.serverURL,
		TenantID:    id.tenantID,
		CollectorID: id.collectorID,
		AuthToken:   id.authToken,
		Version:     Version,
		Handler:     dispatcher,
		Logger:      logger,
	})
	if err != nil {
		logger.Error("wsclient init failed", "err", err)
		return
	}
	logger.Info("collectord starting")
	client.Run(ctx) // returns when ctx is cancelled
	logger.Info("collectord stopped")
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("itom-collector", Version)
		return
	}

	svcConfig := &service.Config{
		Name:        "itom-collector",
		DisplayName: "ITOM Collector",
		Description: "Performs per-site network discovery (firewall, SNMP, active scan) for ITOM.",
	}

	prog := &program{}
	svc, err := service.New(prog, svcConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "service init failed:", err)
		os.Exit(1)
	}

	if args := flag.Args(); len(args) > 0 {
		cmd := args[0]
		switch cmd {
		case "install", "uninstall", "start", "stop", "restart":
			if err := service.Control(svc, cmd); err != nil {
				fmt.Fprintf(os.Stderr, "%s failed: %v\n", cmd, err)
				os.Exit(1)
			}
			fmt.Printf("itom-collector %s: ok\n", cmd)
			return
		case "status":
			st, err := svc.Status()
			if err != nil {
				fmt.Fprintln(os.Stderr, "status:", err)
				os.Exit(1)
			}
			fmt.Println("itom-collector status:", statusName(st))
			return
		case "run":
			// fall through
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
			os.Exit(2)
		}
	}

	if err := svc.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "service run failed:", err)
		os.Exit(1)
	}
}

func statusName(s service.Status) string {
	switch s {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}
