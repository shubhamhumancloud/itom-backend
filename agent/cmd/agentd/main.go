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
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z"
var Version = "0.2.0"

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
		"heartbeatSeconds", cfg.HeartbeatSeconds,
		"maxBatchSize", cfg.MaxBatchSize,
		"maxBufferRows", cfg.MaxBufferRows,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coll := collector.New(log)
	snd := sender.New(cfg.ServerURL, cfg.AgentID, log)

	device := info.Collect(ctx)
	log.Info("device info collected",
		"hostname", device.Hostname,
		"os", device.OS,
		"arch", device.Arch,
		"cpuCores", device.CPUCores,
		"ethernetIPs", device.EthernetIPs,
		"wifiIPs", device.WifiIPs,
		"macAddresses", device.MACAddresses,
	)

	if err := snd.Register(ctx, Version, device); err != nil {
		log.Error("registration failed (will retry on next startup)", "err", err)
	} else {
		log.Info("agent registered")
	}

	started := time.Now()
	batchFull := make(chan struct{}, 1)
	var wg sync.WaitGroup

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
				n, err := buf.Count()
				if err != nil {
					log.Error("buffer count failed", "err", err)
					continue
				}
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
				failures = flushUntilIdle(ctx, log, buf, snd, cfg.MaxBatchSize, failures)
				timer.Reset(jitter(flushDur))
			case <-timer.C:
				failures = flushUntilIdle(ctx, log, buf, snd, cfg.MaxBatchSize, failures)
				timer.Reset(jitter(flushDur))
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			d := jitter(time.Duration(cfg.HeartbeatSeconds) * time.Second)
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
				reqID := uuid.NewString()
				uptime := time.Since(started)
				if err := snd.PostHeartbeat(ctx, Version, uptime, reqID); err != nil {
					log.Warn("heartbeat failed", "err", err)
				}
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info("shutdown signal received", "signal", sig.String())

	cancel()
	wg.Wait()

	log.Info("attempting final metrics flush")
	fctx, fcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fcancel()
	for {
		if err := fctx.Err(); err != nil {
			break
		}
		if err := flushOnceBestEffort(fctx, log, buf, snd, cfg.MaxBatchSize); err != nil {
			break
		}
		n, err := buf.Count()
		if err != nil || n == 0 {
			break
		}
	}
}

func flushUntilIdle(
	ctx context.Context,
	log *logger.Logger,
	buf buffer.Buffer,
	snd *sender.Sender,
	maxBatch int,
	failures int,
) int {
	for {
		select {
		case <-ctx.Done():
			return failures
		default:
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

		decision, err := snd.PostMetricsBatch(ctx, samples, reqID)
		switch decision {
		case sender.MetricsCommitted:
			if err := buf.DeleteUpTo(lastID); err != nil {
				log.Error("buffer delete after send failed", "err", err)
			}
			log.Info("flushed samples", "count", len(samples))
			failures = 0
			continue
		case sender.MetricsDrop:
			if err := buf.DeleteUpTo(lastID); err != nil {
				log.Error("buffer delete after drop failed", "err", err)
			}
			log.Error("dropping batch after non-retryable error", "err", err)
			failures = 0
			continue
		case sender.MetricsRetry:
			d := cappedBackoff(failures)
			failures++
			log.Warn("metrics send failed, backing off", "err", err, "sleep", d.String(), "failures", failures)
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
	snd *sender.Sender,
	maxBatch int,
) error {
	rows, err := buf.PeekBatch(maxBatch)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	samples := make([]collector.Sample, 0, len(rows))
	for _, r := range rows {
		samples = append(samples, r.Sample)
	}
	lastID := rows[len(rows)-1].ID
	reqID := uuid.NewString()
	decision, err := snd.PostMetricsBatch(ctx, samples, reqID)
	if decision == sender.MetricsCommitted {
		if delErr := buf.DeleteUpTo(lastID); delErr != nil {
			log.Error("final flush delete failed", "err", delErr)
			return delErr
		}
		log.Info("final flush succeeded", "count", len(samples))
		return nil
	}
	if decision == sender.MetricsDrop {
		_ = buf.DeleteUpTo(lastID)
		log.Error("final flush dropped batch", "err", err)
		return err
	}
	log.Warn("final flush did not complete", "err", err)
	return err
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
