package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/itom-mini/agent/internal/collector"
	"github.com/itom-mini/agent/internal/logger"
	"github.com/itom-mini/agent/internal/wsclient"
	"github.com/itom-mini/agent/internal/wsproto"
)

// Cadences for the new observability collectors. Best-effort: drop on
// disconnect, re-sample next tick. None of this is buffered.
const (
	procInterval     = 60 * time.Second
	batteryInterval  = 5 * time.Minute
	sensorsInterval  = 60 * time.Second
	gpuInterval      = 60 * time.Second
	softwareInterval = 24 * time.Hour

	obsAckTimeout = 15 * time.Second
)

// startObservability launches one goroutine per collector. Each goroutine
// owns its cadence and short-circuits when the WS is not connected (the
// frame would just fail to ack anyway).
func startObservability(
	ctx context.Context,
	wg *sync.WaitGroup,
	log *logger.Logger,
	wsc *wsclient.Client,
) {
	pc := collector.NewProcessCollector(15, 15)

	// Processes — every 60 s.
	wg.Add(1)
	go runLoop(ctx, wg, log, "processes", procInterval, func() error {
		if !wsc.IsConnected() {
			return nil
		}
		samples, err := pc.Collect(ctx)
		if err != nil || len(samples) == 0 {
			return err
		}
		reqID := uuid.NewString()
		_, err = wsc.SendAcked(ctx, reqID, wsproto.Processes{
			Type:      wsproto.TypeProcesses,
			RequestID: reqID,
			Timestamp: nowISO(),
			Processes: samples,
		}, obsAckTimeout)
		return err
	})

	// Battery — every 5 min, only if a battery is present.
	wg.Add(1)
	go runLoop(ctx, wg, log, "battery", batteryInterval, func() error {
		if !wsc.IsConnected() {
			return nil
		}
		b, err := collector.CollectBattery(ctx)
		if errors.Is(err, collector.ErrNoBattery) {
			return nil // silent on desktops/servers
		}
		if err != nil {
			return err
		}
		reqID := uuid.NewString()
		_, err = wsc.SendAcked(ctx, reqID, wsproto.Battery{
			Type:           wsproto.TypeBattery,
			RequestID:      reqID,
			Timestamp:      nowISO(),
			BatteryReading: *b,
		}, obsAckTimeout)
		return err
	})

	// Sensors — every 60 s.
	wg.Add(1)
	go runLoop(ctx, wg, log, "sensors", sensorsInterval, func() error {
		if !wsc.IsConnected() {
			return nil
		}
		readings, err := collector.CollectSensors(ctx)
		if err != nil || len(readings) == 0 {
			return err
		}
		reqID := uuid.NewString()
		_, err = wsc.SendAcked(ctx, reqID, wsproto.Sensors{
			Type:      wsproto.TypeSensors,
			RequestID: reqID,
			Timestamp: nowISO(),
			Readings:  readings,
		}, obsAckTimeout)
		return err
	})

	// GPU — every 60 s, NVIDIA only. Skip after one failure (no nvidia-smi).
	gpuUnavailable := false
	wg.Add(1)
	go runLoop(ctx, wg, log, "gpu", gpuInterval, func() error {
		if gpuUnavailable || !wsc.IsConnected() {
			return nil
		}
		gpus, err := collector.CollectGPU(ctx)
		if errors.Is(err, collector.ErrNoGPU) {
			gpuUnavailable = true
			log.Info("no NVIDIA GPU detected; GPU collector disabled")
			return nil
		}
		if err != nil || len(gpus) == 0 {
			return err
		}
		reqID := uuid.NewString()
		_, err = wsc.SendAcked(ctx, reqID, wsproto.GPU{
			Type:      wsproto.TypeGPU,
			RequestID: reqID,
			Timestamp: nowISO(),
			GPUs:      gpus,
		}, obsAckTimeout)
		return err
	})

	// Software inventory — once per 24 h, plus once shortly after startup
	// so the UI is populated immediately. If the WS isn't connected or the
	// send fails transiently, retry every `softwareRetryDelay` until one
	// emission succeeds, then drop back to the 24 h cadence. Without this,
	// a WS reconnect race at the 30-second mark would leave the UI empty
	// for a full day.
	swUnavailable := false
	const softwareRetryDelay = 30 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		// emit returns true when we're done for this cycle (success, OS
		// unsupported, or genuinely-empty parser output). false means
		// transient failure — caller should retry after softwareRetryDelay.
		emit := func() bool {
			if swUnavailable {
				return true
			}
			if !wsc.IsConnected() {
				return false
			}
			items, err := collector.CollectSoftware(ctx)
			if errors.Is(err, collector.ErrUnsupportedOS) {
				swUnavailable = true
				log.Info("software inventory not supported on this OS; disabled")
				return true
			}
			if err != nil {
				log.Warn("software collect failed", "err", err)
				return false
			}
			if len(items) == 0 {
				// Parser ran but returned nothing — don't hot-loop; wait for next tick.
				log.Warn("software inventory empty; skipping send")
				return true
			}
			reqID := uuid.NewString()
			_, err = wsc.SendAcked(ctx, reqID, wsproto.SoftwareInventory{
				Type:      wsproto.TypeSoftwareInventory,
				RequestID: reqID,
				Timestamp: nowISO(),
				Items:     items,
			}, 60*time.Second)
			if err != nil {
				log.Warn("software send failed", "err", err)
				return false
			}
			log.Info("software inventory sent", "items", len(items))
			return true
		}
		emitUntilOK := func() {
			for {
				if emit() {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(softwareRetryDelay):
				}
			}
		}
		// Initial attempt shortly after startup.
		select {
		case <-ctx.Done():
			return
		case <-time.After(softwareRetryDelay):
		}
		emitUntilOK()
		t := time.NewTicker(softwareInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				emitUntilOK()
			}
		}
	}()
}

// runLoop is the standard interval+jitter+log envelope shared by short-cadence
// collectors. The fn is called once per tick; errors are logged and tolerated.
func runLoop(
	ctx context.Context,
	wg *sync.WaitGroup,
	log *logger.Logger,
	name string,
	interval time.Duration,
	fn func() error,
) {
	defer wg.Done()
	// Stagger initial run so all collectors don't fire on the same second.
	startupDelay := jitter(interval / 4)
	select {
	case <-ctx.Done():
		return
	case <-time.After(startupDelay):
	}
	for {
		if err := fn(); err != nil {
			log.Warn("collector tick failed", "name", name, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(interval)):
		}
	}
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
