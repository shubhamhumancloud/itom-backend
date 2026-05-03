package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/itom-mini/agent/internal/collector"
	"github.com/itom-mini/agent/internal/config"
	"github.com/itom-mini/agent/internal/info"
	"github.com/itom-mini/agent/internal/logger"
	"github.com/itom-mini/agent/internal/sender"
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z"
var Version = "0.1.0"

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
	log.Info("agent starting",
		"version", Version,
		"agentId", cfg.AgentID,
		"server", cfg.ServerURL,
		"intervalSeconds", cfg.IntervalSeconds,
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	runOnce(ctx, coll, snd, log)

	for {
		select {
		case <-ticker.C:
			runOnce(ctx, coll, snd, log)
		case sig := <-sigCh:
			log.Info("shutdown signal received", "signal", sig.String())
			return
		}
	}
}

func runOnce(ctx context.Context, coll *collector.Collector, snd *sender.Sender, log *logger.Logger) {
	sample, err := coll.Collect(ctx)
	if err != nil {
		log.Error("collect failed", "err", err)
		return
	}
	if err := snd.Send(ctx, sample); err != nil {
		log.Error("send failed", "err", err)
		return
	}
	log.Info("sent",
		"cpu", round2(sample.CPUPercent),
		"mem", round2(sample.MemoryPercent),
		"disk", round2(sample.DiskPercent),
	)
}

func round2(v float64) float64 {
	return float64(int(v*100)) / 100
}
