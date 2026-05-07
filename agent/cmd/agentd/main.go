// Command agentd is the long-running ITOM agent process.
//
// Lifecycle:
//
//  1. Load (or create) the local config file. AgentID is derived
//     deterministically from the host's fingerprint on first boot.
//  2. Open the on-disk SQLite buffer. Recover any samples that were buffered
//     but not yet sent in a previous session.
//  3. Register with the backend over REST POST /v1/agents/register. This is
//     a one-shot bootstrap: the backend learns about the agent, may reassign
//     a canonical agentId, and stores device facts.
//  4. Open a long-lived WebSocket to /v1/ws. From here on:
//       - metrics flow over WS (with server acks)
//       - liveness is the WS connection itself (no REST heartbeat anymore)
//       - server can push config / commands at any time (future)
//  5. The collector keeps writing samples to the buffer regardless of WS
//     state. The flusher drains the buffer through the WS client; if WS is
//     down, samples accumulate on disk until reconnect.
//  6. On SIGINT/SIGTERM: cancel context, attempt one final flush, exit.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"sync"
	"syscall"
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
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z"
var Version = "0.3.0"

const (
	// How long to wait for an ack before treating a metrics send as failed.
	ackTimeout = 30 * time.Second
)

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

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	bufPath, err := buffer.DefaultPath()
	if err != nil {
		log.Error("buffer path failed", "err", err)
		os.Exit(1)
	}
	buf, err := buffer.Open(bufPath, cfg.MaxBufferRows, log)
	if err != nil {
		log.Error("buffer open failed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = buf.Close() }()

	pending, err := buf.Count()
	if err != nil {
		log.Error("buffer count failed", "err", err)
		os.Exit(1)
	}
	log.Info("buffer status", "pendingSamples", pending)

	log.Info("agent starting",
		"version", Version,
		"agentId", cfg.AgentID,
		"server", cfg.ServerURL,
		"intervalSeconds", cfg.IntervalSeconds,
		"flushSeconds", cfg.FlushSeconds,
		"maxBatchSize", cfg.MaxBatchSize,
		"maxBufferRows", cfg.MaxBufferRows,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
			if err := config.Save(*configPath, cfg); err != nil {
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
			if err := config.Save(*configPath, cfg); err != nil {
				log.Error("persist reassigned agentId failed", "err", err)
			}
		},
	})
	if err != nil {
		log.Error("wsclient init failed", "err", err)
		os.Exit(1)
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

	// --- Shutdown ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info("shutdown signal received", "signal", sig.String())

	cancel()
	wg.Wait()

	log.Info("attempting final metrics flush")
	fctx, fcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fcancel()
	// Best-effort final flush. WS may already be closed; that's fine — buffer
	// keeps the data for next startup.
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
			// Don't burn a backoff cycle just because the connection is
			// transiently down — wsclient is reconnecting on its own.
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
			// Server explicitly rejected — drop so we don't loop forever.
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
