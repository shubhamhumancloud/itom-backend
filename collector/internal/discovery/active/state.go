package active

import (
	"sync"
	"time"

	"github.com/itom-mini/collector/internal/cidrguard"
	"github.com/itom-mini/collector/internal/wsproto"
)

// runState holds the per-run shared state. Concurrent access from
// many host-workers — every mutating method takes s.mu.
type runState struct {
	log     Logger
	guard   *cidrguard.Guard
	emit    func([]wsproto.Observation) error

	mu       sync.Mutex
	batch    []wsproto.Observation
	totalObs int
	stats    Stats
	rates    *rateLimiter
}

func newRunState(log Logger, guard *cidrguard.Guard, emit func([]wsproto.Observation) error, cfg Config) *runState {
	return &runState{
		log:   log,
		guard: guard,
		emit:  emit,
		batch: make([]wsproto.Observation, 0, 200),
		rates: newRateLimiter(cfg.RateLimitPPS),
	}
}

// emitObs queues one observation. Locks internally.
func (s *runState) emitObs(o wsproto.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batch = append(s.batch, o)
	s.totalObs++
	if len(s.batch) >= 200 {
		s.flushLocked()
	}
}

func (s *runState) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushLocked()
}

func (s *runState) flushLocked() {
	if len(s.batch) == 0 {
		return
	}
	toSend := make([]wsproto.Observation, len(s.batch))
	copy(toSend, s.batch)
	s.batch = s.batch[:0]
	if err := s.emit(toSend); err != nil {
		s.log.Warn("active: emit failed", "err", err)
	}
}

// ts returns the time formatted for observations.
func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
