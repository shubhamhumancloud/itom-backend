// Package crawl implements the seed-and-walk discovery loop.
//
// Given a list of seed IPs, the crawler:
//   1. Pops the next unvisited IP from the queue.
//   2. Checks the CIDR allowlist; logs + skips if outside.
//   3. Runs the fingerprint probe ladder.
//   4. Looks up a Driver for the resulting vendor; if none, emits an
//      "unknown_device" observation and moves on.
//   5. Calls driver.Ingest(). On success:
//        - records the chassis ID in the visited set (dedup);
//        - emits a chassis_alias observation if we'd already seen
//          this chassis under a different management IP;
//        - appends observations to the output stream;
//        - pushes neighbour hints onto the queue.
//   6. Repeats until the queue empties, MaxDepth hits, or MaxDevices
//      reached.
//
// Concurrency: bounded worker pool sized by Options.MaxConcurrency
// (default 8). Within a worker, walks against one device are
// sequential — gosnmp does not allow concurrent in-flight requests
// per session, and chapter-2 politeness rules say "one session per
// device, walks sequential."
package crawl

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/itom-mini/collector/internal/cidrguard"
	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/driver"
	"github.com/itom-mini/collector/internal/discovery/fingerprint"
	"github.com/itom-mini/collector/internal/wsproto"
)

// Logger matches the slim interface used by wsclient.
type Logger interface {
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

// Options tunes the crawl.
type Options struct {
	MaxDepth        int
	MaxDevices      int
	MaxConcurrency  int // workers across devices; default 8
	FingerprintOpts fingerprint.Options
}

// Crawler holds the dependencies. Reuse across jobs is safe.
type Crawler struct {
	Registry *driver.Registry
	Guard    *cidrguard.Guard
	Log      Logger
}

// Stats is the summary the crawler returns alongside observations.
type Stats struct {
	DevicesVisited       int
	DevicesIdentified    int
	DevicesUnknown       int
	DevicesRefusedByCIDR int
	DevicesAuthFailed    int
	DevicesUnreachable   int
	DriverFailures       int
	ChassisAliases       int
	Hops                 int
}

// EmitChunk streams observations back to the dispatcher.
type EmitChunk func(observations []wsproto.Observation) error

// Seed is one entry in the starting list.
type Seed struct {
	IP         string
	VendorHint device.Vendor
}

// Run walks the network starting from `seeds`.
//
// Concurrency model:
//   - One producer/consumer goroutine per worker, fed by a shared
//     channel of "to-visit" entries.
//   - One supervisor goroutine that owns the shared mutex-protected
//     state (visited sets, stats, output buffer) and exits when all
//     workers are idle AND the channel is empty.
//   - Emit happens under the same mutex so the BE sees coherent
//     batches; chunking is by observation count, not device count.
func (c *Crawler) Run(
	ctx context.Context,
	seeds []Seed,
	creds device.Creds,
	opts Options,
	emit EmitChunk,
) (int, Stats, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 3
	}
	if opts.MaxDevices <= 0 {
		opts.MaxDevices = 256
	}
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 8
	}

	state := &runState{
		log:         c.Log,
		guard:       c.Guard,
		registry:    c.Registry,
		fpOpts:      opts.FingerprintOpts,
		creds:       creds,
		maxDepth:    opts.MaxDepth,
		maxDevices:  opts.MaxDevices,
		numWorkers:  opts.MaxConcurrency,
		seenIPs:     map[string]bool{},
		seenChassis: map[string]string{}, // chassisID → first-seen IP
		batch:       make([]wsproto.Observation, 0, 200),
		emit:        emit,
	}

	// Pre-seed the queue.
	for _, s := range seeds {
		state.enqueue(queued{
			ip:    s.IP,
			depth: 0,
			hint:  device.NeighbourHint{IP: s.IP, Reason: "seed", VendorHint: s.VendorHint},
		})
	}

	// Worker pool. A single shared queue with a condition variable
	// (instead of a channel) keeps depth/visit decisions atomic with
	// the dequeue — important because two workers must NOT both pull
	// the same IP from competing channel reads.
	var wg sync.WaitGroup
	for i := 0; i < opts.MaxConcurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			state.workerLoop(ctx, workerID)
		}(i)
	}
	wg.Wait()

	if err := state.flush(); err != nil {
		return state.totalObs, state.stats, err
	}
	if state.firstErr != nil {
		return state.totalObs, state.stats, state.firstErr
	}
	c.Log.Info("crawl complete",
		"devicesVisited", state.stats.DevicesVisited,
		"identified", state.stats.DevicesIdentified,
		"unknown", state.stats.DevicesUnknown,
		"refusedByCidr", state.stats.DevicesRefusedByCIDR,
		"authFailed", state.stats.DevicesAuthFailed,
		"unreachable", state.stats.DevicesUnreachable,
		"driverFailures", state.stats.DriverFailures,
		"chassisAliases", state.stats.ChassisAliases,
		"maxHops", state.stats.Hops,
	)
	return state.totalObs, state.stats, nil
}

// ----- internals -----

type queued struct {
	ip    string
	depth int
	hint  device.NeighbourHint
}

type runState struct {
	log      Logger
	guard    *cidrguard.Guard
	registry *driver.Registry
	fpOpts   fingerprint.Options
	creds    device.Creds
	maxDepth   int
	maxDevices int
	numWorkers int

	mu sync.Mutex
	cond        *sync.Cond // initialised lazily
	queue       []queued
	seenIPs     map[string]bool
	seenChassis map[string]string // chassisID → first-seen IP
	idleWorkers int

	batch    []wsproto.Observation
	emit     EmitChunk
	totalObs int
	stats    Stats
	firstErr error
	done     bool
}

func (s *runState) enqueue(q queued) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queueLocked(q)
}

// queueLocked assumes the caller holds s.mu.
func (s *runState) queueLocked(q queued) {
	if s.cond == nil {
		s.cond = sync.NewCond(&s.mu)
	}
	if s.seenIPs[q.ip] {
		return
	}
	s.queue = append(s.queue, q)
	s.cond.Signal()
}

// dequeue blocks until either an item is available or all workers are
// idle (meaning the crawl is done). Returns ok=false when the crawl
// should terminate.
func (s *runState) dequeue() (queued, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cond == nil {
		s.cond = sync.NewCond(&s.mu)
	}
	for {
		if s.done {
			return queued{}, false
		}
		if len(s.queue) > 0 {
			head := s.queue[0]
			s.queue = s.queue[1:]
			return head, true
		}
		// No work for me right now. If every other worker is also
		// idle, the crawl is over — wake them up to exit.
		s.idleWorkers++
		if s.idleWorkers >= s.numWorkers {
			s.done = true
			s.cond.Broadcast()
			return queued{}, false
		}
		s.cond.Wait()
		s.idleWorkers--
	}
}

// workerLoop is what each goroutine runs.
func (s *runState) workerLoop(ctx context.Context, workerID int) {
	for {
		if ctx.Err() != nil {
			s.recordErr(ctx.Err())
			s.mu.Lock()
			s.done = true
			if s.cond != nil {
				s.cond.Broadcast()
			}
			s.mu.Unlock()
			return
		}
		q, ok := s.dequeue()
		if !ok {
			return
		}
		s.processOne(ctx, q)
	}
}

// processOne handles a single dequeued IP.
func (s *runState) processOne(ctx context.Context, q queued) {
	// CIDR check first — refuse before any packets leave.
	if s.guard != nil && !s.guard.AllowString(q.ip) {
		s.mu.Lock()
		s.stats.DevicesRefusedByCIDR++
		s.addObs(wsproto.Observation{
			SubjectKind: "device",
			SubjectKey:  fmt.Sprintf("ip:%s", q.ip),
			Attribute:   "refused",
			Value: map[string]any{
				"reason":   "out_of_cidr_allowlist",
				"sourceIp": q.hint.IP,
				"hint":     q.hint.Reason,
			},
			SeenAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
		s.mu.Unlock()
		return
	}

	// Atomic claim: mark IP as seen so other workers won't pick the
	// same row up if it's enqueued twice.
	s.mu.Lock()
	if s.seenIPs[q.ip] {
		s.mu.Unlock()
		return
	}
	s.seenIPs[q.ip] = true
	if s.stats.DevicesVisited >= s.maxDevices {
		s.mu.Unlock()
		return
	}
	s.stats.DevicesVisited++
	if q.depth > s.stats.Hops {
		s.stats.Hops = q.depth
	}
	s.mu.Unlock()

	// Fingerprint (network I/O — no mutex held).
	deviceCreds := s.creds
	deviceCreds.Host = q.ip
	fp, ferr := fingerprint.Identify(ctx, q.ip, deviceCreds, s.fpOpts)
	if ferr != nil {
		s.recordErr(ferr)
		return
	}

	s.mu.Lock()
	s.addObs(wsproto.Observation{
		SubjectKind: "device",
		SubjectKey:  fmt.Sprintf("ip:%s", q.ip),
		Attribute:   "fingerprint",
		Value: map[string]any{
			"vendor":      string(fp.Vendor),
			"confidence":  fp.Confidence.String(),
			"openPorts":   fp.OpenTCPPorts,
			"tlsSubject":  fp.TLSSubject,
			"tlsIssuer":   fp.TLSIssuer,
			"sshBanner":   fp.SSHBanner,
			"httpServer":  fp.HTTPServer,
			"sysObjectId": fp.SysObjectID,
			"reasons":     fp.Reasons,
			"fromHint":    q.hint.Reason,
			"depth":       q.depth,
		},
		SeenAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	s.mu.Unlock()

	// Driver selection: hint wins if confidence isn't high.
	vendor := fp.Vendor
	if q.hint.VendorHint != "" && fp.Confidence < device.ConfidenceHigh {
		vendor = q.hint.VendorHint
	}
	drv := s.registry.Pick(vendor)
	if drv == nil {
		s.mu.Lock()
		s.stats.DevicesUnknown++
		s.mu.Unlock()
		s.log.Info("no driver for vendor; recording fingerprint only",
			"ip", q.ip, "vendor", string(vendor))
		return
	}

	// Ingest (network I/O — no mutex held).
	res, err := drv.Ingest(ctx, deviceCreds)
	if err != nil {
		s.handleDriverError(q.ip, vendor, err)
		return
	}

	// Chassis dedup decision is the new mutex-held critical section.
	s.mu.Lock()
	if res.ChassisID != "" {
		if firstIP, seen := s.seenChassis[res.ChassisID]; seen && firstIP != q.ip {
			// We've already crawled this chassis under another IP.
			// Emit an alias row and skip the ingest results — they'd
			// be duplicates.
			s.stats.ChassisAliases++
			s.addObs(wsproto.Observation{
				SubjectKind: "chassis_alias",
				SubjectKey: fmt.Sprintf(
					"chassis:%s|alias:%s", res.ChassisID, q.ip,
				),
				Attribute: "binding",
				Value: map[string]any{
					"chassisId":  res.ChassisID,
					"firstIp":    firstIP,
					"aliasIp":    q.ip,
					"hintReason": q.hint.Reason,
				},
				SeenAt: time.Now().UTC().Format(time.RFC3339Nano),
			})
			s.mu.Unlock()
			return
		}
		s.seenChassis[res.ChassisID] = q.ip
	}
	s.stats.DevicesIdentified++
	for _, o := range res.Observations {
		s.addObs(o)
	}
	s.totalObs += len(res.Observations)
	// Enqueue neighbours under the same lock — cheap, and lets us
	// dedup against seenIPs and seenChassis atomically.
	if q.depth < s.maxDepth {
		for _, n := range res.Neighbours {
			if n.IP == "" || s.seenIPs[n.IP] {
				continue
			}
			s.queueLocked(queued{
				ip:    n.IP,
				depth: q.depth + 1,
				hint:  n,
			})
		}
	}
	s.mu.Unlock()
}

// handleDriverError classifies and records an ingest failure.
func (s *runState) handleDriverError(ip string, vendor device.Vendor, err error) {
	reason := "ingest_failed"
	switch {
	case isAuthErr(err):
		reason = "auth_failed"
		s.mu.Lock()
		s.stats.DevicesAuthFailed++
		s.mu.Unlock()
	case isUnreachableErr(err):
		reason = "unreachable"
		s.mu.Lock()
		s.stats.DevicesUnreachable++
		s.mu.Unlock()
	default:
		s.mu.Lock()
		s.stats.DriverFailures++
		s.mu.Unlock()
	}
	s.log.Warn("driver ingest failed; continuing",
		"ip", ip, "vendor", string(vendor), "err", err, "reason", reason)
	s.mu.Lock()
	s.addObs(wsproto.Observation{
		SubjectKind: "device",
		SubjectKey:  fmt.Sprintf("ip:%s", ip),
		Attribute:   reason,
		Value: map[string]any{
			"vendor": string(vendor),
			"error":  err.Error(),
		},
		SeenAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	s.mu.Unlock()
}

func isAuthErr(err error) bool {
	var a *device.ErrAuth
	return errors.As(err, &a)
}
func isUnreachableErr(err error) bool {
	var u *device.ErrUnreachable
	return errors.As(err, &u)
}

// addObs appends to the buffer; flushes if full. Caller holds s.mu.
func (s *runState) addObs(o wsproto.Observation) {
	s.batch = append(s.batch, o)
	if len(s.batch) >= 200 {
		s.flushLocked()
	}
}

func (s *runState) flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

func (s *runState) flushLocked() error {
	if len(s.batch) == 0 {
		return nil
	}
	toSend := make([]wsproto.Observation, len(s.batch))
	copy(toSend, s.batch)
	s.batch = s.batch[:0]
	if err := s.emit(toSend); err != nil {
		if s.firstErr == nil {
			s.firstErr = err
		}
		s.done = true
		if s.cond != nil {
			s.cond.Broadcast()
		}
		return err
	}
	return nil
}

func (s *runState) recordErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firstErr == nil {
		s.firstErr = err
	}
}
