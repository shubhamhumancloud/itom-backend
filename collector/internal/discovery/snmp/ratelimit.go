package snmp

import (
	"sync"
	"time"
)

// tokenBucket caps SNMP requests per second per Client. Tiny, in-house
// implementation rather than golang.org/x/time/rate so we don't pull a
// new dependency for one rate-limit knob.
//
// Algorithm: bucket of size `rate` (one second of tokens). Each
// take() consumes one; if empty, sleep until the next refill. Refill
// happens lazily on take() using wall-clock — no background goroutine.
type tokenBucket struct {
	mu        sync.Mutex
	rate      int           // tokens added per second (== bucket capacity)
	tokens    int           // currently available
	lastRefill time.Time
}

func newTokenBucket(rate int) *tokenBucket {
	if rate <= 0 {
		return nil
	}
	return &tokenBucket{
		rate:       rate,
		tokens:     rate,
		lastRefill: time.Now(),
	}
}

// take consumes one token, blocking until one is available.
func (b *tokenBucket) take() {
	for {
		b.mu.Lock()
		b.refillLocked()
		if b.tokens > 0 {
			b.tokens--
			b.mu.Unlock()
			return
		}
		// Bucket empty — compute how long until at least one token.
		// Use the time-to-next-token derived from the rate.
		wait := time.Second / time.Duration(b.rate)
		b.mu.Unlock()
		time.Sleep(wait)
	}
}

// refillLocked adds tokens proportional to elapsed time, capped at
// the bucket size. Caller holds b.mu.
func (b *tokenBucket) refillLocked() {
	now := time.Now()
	elapsed := now.Sub(b.lastRefill)
	if elapsed <= 0 {
		return
	}
	add := int(elapsed.Seconds() * float64(b.rate))
	if add <= 0 {
		return
	}
	b.tokens += add
	if b.tokens > b.rate {
		b.tokens = b.rate
	}
	b.lastRefill = now
}
