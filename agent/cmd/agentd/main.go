// Command agentd is the long-running ITOM agent process.
//
// Lifecycle:
//
//  1. Read the baked-in identity (tenantId + serverUrl) from compile-time vars
//     that the backend overwrites at install-request time. Refuse to run if
//     the placeholder is still present (i.e. someone tried to run a raw
//     template).
//  2. Load (or create) the local config file. AgentID is derived
//     deterministically from the host's fingerprint on first boot.
//  3. Open the on-disk SQLite buffer. Recover any samples that were buffered
//     but not yet sent in a previous session.
//  4. Register with the backend over REST POST /v1/agents/register.
//  5. Open a long-lived WebSocket to /v1/ws.
//  6. On SIGINT/SIGTERM (or service stop): cancel context, attempt one final
//     flush, exit.
//
// CLI surface (provided by kardianos/service):
//
//   itom-agent install      register with the OS service manager
//   itom-agent uninstall    unregister from the OS service manager
//   itom-agent start        ask the service manager to start it
//   itom-agent stop         ask the service manager to stop it
//   itom-agent restart      stop + start
//   itom-agent status       service status
//   itom-agent run          run in the foreground (default when no args)
//   itom-agent version      print version
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/itom-mini/agent/internal/buffer"
	"github.com/itom-mini/agent/internal/collector"
	"github.com/itom-mini/agent/internal/config"
	"github.com/itom-mini/agent/internal/info"
	"github.com/itom-mini/agent/internal/logger"
	"github.com/itom-mini/agent/internal/sender"
	"github.com/itom-mini/agent/internal/wsclient"
	"github.com/itom-mini/agent/internal/wsproto"
	"github.com/kardianos/service"
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z"
var Version = "0.4.0"

// Patchable identity, written by the backend's BinaryPatcherService at
// install-request time. The placeholder defaults below are the literal byte
// strings the patcher searches for in the compiled binary; they MUST be
// unique enough that no other code section accidentally matches.
//
// Layout (must NOT change without also updating the patcher constants):
//   bakedTenantID   — 64 bytes total, prefix "ITOMBAKED_TENANT_ID:"
//   bakedServerURL  — 256 bytes total, prefix "ITOMBAKED_SERVER_URL:"
//
// The patcher overwrites the entire region with the tenant value followed by
// NUL padding so the byte length stays identical (Go string headers carry a
// fixed len; only the content bytes are patched).
//
// `var` (not `const`): const literals can be folded into instructions and
// would not be patchable. With var, the compiler emits the literal into
// .rodata and the variable header points there — patchable on disk.
//
// Lengths are asserted in init() below; any miscount fails at startup.
var (
	bakedTenantID = "ITOMBAKED_TENANT_ID:" + // 20 chars
		"__________" + "__________" + "__________" + "__________" + "____" // 44 chars  → 64

	bakedServerURL = "ITOMBAKED_SERVER_URL:" + // 21 chars
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

	// How long to wait for an ack before treating a metrics send as failed.
	ackTimeout = 30 * time.Second
)

func init() {
	if len(bakedTenantID) != tenantIDLen {
		panic(fmt.Sprintf("bakedTenantID length is %d; want %d (placeholder miscount)",
			len(bakedTenantID), tenantIDLen))
	}
	if len(bakedServerURL) != serverURLLen {
		panic(fmt.Sprintf("bakedServerURL length is %d; want %d (placeholder miscount)",
			len(bakedServerURL), serverURLLen))
	}
}

// resolveBaked returns the patched identity, or an error if the binary still
// contains the placeholder (i.e. it was never patched by the backend).
func resolveBaked() (tenantID, serverURL string, err error) {
	tid := strings.TrimRight(bakedTenantID, bakedPadCutset)
	url := strings.TrimRight(bakedServerURL, bakedPadCutset)

	if strings.HasPrefix(tid, tenantIDPrefix) {
		return "", "", fmt.Errorf(
			"tenant id was not patched into this binary; you must download " +
				"itom-agent from your tenant's install page, not run a raw template")
	}
	if strings.HasPrefix(url, serverURLPrefix) {
		return "", "", fmt.Errorf(
			"server url was not patched into this binary; you must download " +
				"itom-agent from your tenant's install page, not run a raw template")
	}
	return tid, url, nil
}

// program is the long-running unit kardianos/service controls.
type program struct {
	cfgPath string
	wg      sync.WaitGroup
	cancel  context.CancelFunc
	log     *logger.Logger
}

// Start is non-blocking — kardianos calls it once to launch the worker.
func (p *program) Start(_ service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		runAgent(ctx, p.log, p.cfgPath)
	}()
	return nil
}

// Stop is called by the service manager (or by service.Run on SIGINT in
// interactive mode). It cancels the context and waits for runAgent to exit.
func (p *program) Stop(_ service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		// Best effort — don't hang the service manager forever.
	}
	return nil
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", "", "path to config file (default: ~/.itom-agent/config.json)")
	flag.Parse()

	if *showVersion {
		fmt.Println("itom-agent", Version)
		return
	}

	log, err := logger.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to init logger:", err)
		os.Exit(1)
	}

	tenantID, serverURL, err := resolveBaked()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// Make sure config picks up the baked values on first boot. Subsequent
	// runs read these from the persisted config but env-style overrides are
	// no longer honoured.
	if err := os.Setenv("ITOM_TENANT_ID", tenantID); err != nil {
		log.Warn("failed to seed tenant env", "err", err)
	}
	if err := os.Setenv("ITOM_SERVER_URL", serverURL); err != nil {
		log.Warn("failed to seed server env", "err", err)
	}

	prog := &program{cfgPath: *configPath, log: log}

	svcConfig := &service.Config{
		Name:        "itom-agent",
		DisplayName: "ITOM Agent",
		Description: "Collects host telemetry for the ITOM platform.",
	}

	svc, err := service.New(prog, svcConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "service init failed:", err)
		os.Exit(1)
	}

	// Subcommand handling (install/start/stop/uninstall/etc.) — only when
	// invoked from a terminal. When the OS service manager invokes us there
	// are no extra positional args.
	if args := flag.Args(); len(args) > 0 {
		cmd := args[0]
		switch cmd {
		case "install", "uninstall", "start", "stop", "restart":
			if err := service.Control(svc, cmd); err != nil {
				fmt.Fprintf(os.Stderr, "%s failed: %v\n", cmd, err)
				os.Exit(1)
			}
			fmt.Printf("itom-agent %s: ok\n", cmd)
			return
		case "status":
			st, err := svc.Status()
			if err != nil {
				fmt.Fprintln(os.Stderr, "status:", err)
				os.Exit(1)
			}
			fmt.Println("itom-agent status:", statusName(st))
			return
		case "run":
			// Explicit foreground run; falls through to svc.Run below.
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
			fmt.Fprintln(os.Stderr, "valid: install, uninstall, start, stop, restart, status, run, version")
			os.Exit(2)
		}
	}

	// Bare invocation (no args) or "run": works both interactively and when
	// invoked by the OS service manager. service.Run blocks; on SIGINT in
	// interactive mode it calls Stop and returns.
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

// runAgent is the original main loop, lifted into a function so it can be
// driven by kardianos service Start/Stop. It exits when ctx is cancelled.
func runAgent(ctx context.Context, log *logger.Logger, configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		return
	}

	bufPath, err := buffer.DefaultPath()
	if err != nil {
		log.Error("buffer path failed", "err", err)
		return
	}
	buf, err := buffer.Open(bufPath, cfg.MaxBufferRows, log)
	if err != nil {
		log.Error("buffer open failed", "err", err)
		return
	}
	defer func() { _ = buf.Close() }()

	pending, err := buf.Count()
	if err != nil {
		log.Error("buffer count failed", "err", err)
		return
	}
	log.Info("buffer status", "pendingSamples", pending)

	log.Info("agent starting",
		"version", Version,
		"agentId", cfg.AgentID,
		"server", cfg.ServerURL,
		"tenantId", cfg.TenantID,
		"intervalSeconds", cfg.IntervalSeconds,
		"flushSeconds", cfg.FlushSeconds,
		"maxBatchSize", cfg.MaxBatchSize,
		"maxBufferRows", cfg.MaxBufferRows,
	)

	coll := collector.New(log)

	// --- 1. REST register (bootstrap) ---
	snd := sender.New(cfg.ServerURL, cfg.AgentID, cfg.TenantID, log)
	device := info.Collect(ctx)
	log.Info("device info collected",
		"hostname", device.Hostname,
		"os", device.OS,
		"arch", device.Arch,
		"cpuCores", device.CPUCores,
		"macAddresses", device.MACAddresses,
	)

	resp, err := snd.Register(ctx, Version, cfg.FingerprintHash, device)
	if err != nil {
		log.Error("registration failed (will retry over WS hello)", "err", err)
	} else {
		if resp != nil && resp.Reassigned && resp.AgentID != "" && resp.AgentID != cfg.AgentID {
			log.Info("agent reassigned by backend (fingerprint match)",
				"oldAgentId", cfg.AgentID,
				"newAgentId", resp.AgentID,
			)
			cfg.AgentID = resp.AgentID
			if err := config.Save(configPath, cfg); err != nil {
				log.Error("persist reassigned agentId failed", "err", err)
			}
		}
		log.Info("agent registered (REST)", "agentId", cfg.AgentID)
	}

	// --- 2. WebSocket client ---
	wsc, err := wsclient.New(wsclient.Config{
		ServerURL:       cfg.ServerURL,
		AgentID:         cfg.AgentID,
		AgentVersion:    Version,
		FingerprintHash: cfg.FingerprintHash,
		Logger:          log,
		OnReassign: func(newID string) {
			cfg.AgentID = newID
			if err := config.Save(configPath, cfg); err != nil {
				log.Error("persist reassigned agentId failed", "err", err)
			}
		},
	})
	if err != nil {
		log.Error("wsclient init failed", "err", err)
		return
	}

	batchFull := make(chan struct{}, 1)
	var wg sync.WaitGroup

	// --- 3. Collector goroutine: tick → sample → buffer ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			d := jitter(time.Duration(cfg.IntervalSeconds) * time.Second)
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
				sample, err := coll.Collect(ctx)
				if err != nil {
					log.Error("collect failed", "err", err)
					continue
				}
				if err := buf.Append(sample); err != nil {
					log.Error("buffer append failed", "err", err)
					continue
				}
				n, _ := buf.Count()
				log.Debug("buffered sample", "count", n)
				if n >= cfg.MaxBatchSize {
					select {
					case batchFull <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	// --- 4. WS connection manager: dial + hello + reconnect ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		wsc.Run(ctx)
	}()

	// --- 5. Flusher: drain buffer through WS, gated by connection state ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		failures := 0
		flushDur := time.Duration(cfg.FlushSeconds) * time.Second
		timer := time.NewTimer(jitter(flushDur))
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-batchFull:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				failures = flushUntilIdle(ctx, log, buf, wsc, cfg.MaxBatchSize, failures)
				timer.Reset(jitter(flushDur))
			case <-timer.C:
				failures = flushUntilIdle(ctx, log, buf, wsc, cfg.MaxBatchSize, failures)
				timer.Reset(jitter(flushDur))
			}
		}
	}()

	// --- 6. Observability collectors (best-effort, no buffering) ---
	startObservability(ctx, &wg, log, wsc)

	// --- Wait for cancellation, then attempt final flush ---
	<-ctx.Done()
	log.Info("shutdown signal received")

	wg.Wait()

	log.Info("attempting final metrics flush")
	fctx, fcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fcancel()
	_ = flushOnceBestEffort(fctx, log, buf, wsc, cfg.MaxBatchSize)
}

// flushUntilIdle drains the buffer, sending one batch at a time over WS and
// waiting for an ack before deleting. If WS is disconnected or sends fail,
// backs off and returns — the next tick will retry.
func flushUntilIdle(
	ctx context.Context,
	log *logger.Logger,
	buf buffer.Buffer,
	wsc *wsclient.Client,
	maxBatch int,
	failures int,
) int {
	for {
		if err := ctx.Err(); err != nil {
			return failures
		}

		if !wsc.IsConnected() {
			return failures
		}

		rows, err := buf.PeekBatch(maxBatch)
		if err != nil {
			log.Error("peek batch failed", "err", err)
			return failures
		}
		if len(rows) == 0 {
			return failures
		}

		samples := make([]collector.Sample, 0, len(rows))
		for _, r := range rows {
			samples = append(samples, r.Sample)
		}
		lastID := rows[len(rows)-1].ID
		reqID := uuid.NewString()

		result, err := wsc.SendMetrics(ctx, samples, reqID, ackTimeout)
		switch {
		case err == nil && (result == wsproto.AckCommitted || result == wsproto.AckDuplicate):
			if err := buf.DeleteUpTo(lastID); err != nil {
				log.Error("buffer delete after send failed", "err", err)
			}
			log.Info("flushed samples", "count", len(samples), "result", result)
			failures = 0
			continue

		case err == nil && result == wsproto.AckRejected:
			if err := buf.DeleteUpTo(lastID); err != nil {
				log.Error("buffer delete after reject failed", "err", err)
			}
			log.Error("server rejected batch (dropping)", "count", len(samples))
			failures = 0
			continue

		default:
			d := cappedBackoff(failures)
			failures++
			log.Warn("metrics send failed, backing off",
				"err", err,
				"sleep", d.String(),
				"failures", failures)
			select {
			case <-ctx.Done():
				return failures
			case <-time.After(jitter(d)):
			}
		}
	}
}

func flushOnceBestEffort(
	ctx context.Context,
	log *logger.Logger,
	buf buffer.Buffer,
	wsc *wsclient.Client,
	maxBatch int,
) error {
	if !wsc.IsConnected() {
		return nil
	}
	rows, err := buf.PeekBatch(maxBatch)
	if err != nil || len(rows) == 0 {
		return err
	}
	samples := make([]collector.Sample, 0, len(rows))
	for _, r := range rows {
		samples = append(samples, r.Sample)
	}
	lastID := rows[len(rows)-1].ID
	reqID := uuid.NewString()

	result, err := wsc.SendMetrics(ctx, samples, reqID, 3*time.Second)
	if err != nil {
		log.Warn("final flush failed", "err", err)
		return err
	}
	if result == wsproto.AckCommitted || result == wsproto.AckDuplicate {
		if delErr := buf.DeleteUpTo(lastID); delErr != nil {
			log.Error("final flush delete failed", "err", delErr)
			return delErr
		}
		log.Info("final flush succeeded", "count", len(samples))
	}
	return nil
}

func cappedBackoff(failuresBefore int) time.Duration {
	const max = 5 * time.Minute
	n := failuresBefore
	if n < 0 {
		n = 0
	}
	if n > 20 {
		n = 20
	}
	d := time.Duration(5) * time.Second * time.Duration(uint64(1)<<uint(n))
	if d > max {
		d = max
	}
	return d
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	low := float64(d) * 0.75
	high := float64(d) * 1.25
	return time.Duration(low + rand.Float64()*(high-low))
}
