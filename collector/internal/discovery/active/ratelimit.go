package active

import (
	"net/netip"
	"sync"
	"time"
)

// rateLimiter holds one token bucket per /24 subnet. Every packet
// the scanner sends takes one token. Buckets are created lazily on
// first packet to a given subnet.
//
// Why per-/24 and not per-host: chapter-3 doc rate cap is "1000 PPS
// per /24" — the unit is the subnet, not the IP. Same probe sweep
// across many subnets in parallel sends at N * limit aggregate PPS,
// which is what we want.
type rateLimiter struct {
	pps int
	mu  sync.Mutex
	bys map[string]*activeBucket
}

func newRateLimiter(pps int) *rateLimiter {
	if pps <= 0 {
		pps = 1000
	}
	return &rateLimiter{pps: pps, bys: map[string]*activeBucket{}}
}

// take blocks until the subnet of ip can accept another packet.
func (r *rateLimiter) take(ip string) {
	key := subnetOf(ip)
	r.mu.Lock()
	b, ok := r.bys[key]
	if !ok {
		b = newBucket(r.pps)
		r.bys[key] = b
	}
	r.mu.Unlock()
	b.take()
}

// subnetOf returns the /24 (v4) or /64 (v6) that ip falls into. Used
// as the map key so multiple IPs in the same subnet share one bucket.
func subnetOf(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if addr.Is4() {
		// /24 — keep first 3 octets.
		b4 := addr.As4()
		return netip.AddrFrom4([4]byte{b4[0], b4[1], b4[2], 0}).String() + "/24"
	}
	// /64 — keep first 8 bytes.
	b16 := addr.As16()
	var trimmed [16]byte
	copy(trimmed[:8], b16[:8])
	return netip.AddrFrom16(trimmed).String() + "/64"
}

// activeBucket is the same shape as snmp.tokenBucket but kept in this
// package to avoid the cross-package import (and the snmp limiter
// counts SNMP PDUs only, not active-scan packets).
type activeBucket struct {
	mu         sync.Mutex
	rate       int
	tokens     int
	lastRefill time.Time
}

func newBucket(rate int) *activeBucket {
	return &activeBucket{rate: rate, tokens: rate, lastRefill: time.Now()}
}

func (b *activeBucket) take() {
	for {
		b.mu.Lock()
		b.refillLocked()
		if b.tokens > 0 {
			b.tokens--
			b.mu.Unlock()
			return
		}
		wait := time.Second / time.Duration(b.rate)
		b.mu.Unlock()
		time.Sleep(wait)
	}
}

func (b *activeBucket) refillLocked() {
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
