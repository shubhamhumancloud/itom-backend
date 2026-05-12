package active

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// discoverHost is stage 1. We run three probes in parallel and take
// the first "yes": ICMP echo (unprivileged), TCP-ping to 443, TCP-ping
// to 445. ICMP-blocked Windows boxes still respond on 445 + 3389.
//
// Cross-platform notes:
//   - pro-bing's default mode is UDP datagram on Linux/macOS (needs the
//     ping_group_range sysctl on some distros) and uses the Windows
//     IcmpSendEcho API on Windows. Either way, no admin needed.
//   - If unprivileged ICMP is blocked at the kernel, the TCP probes
//     still detect any non-firewalled host. Net result: false-negatives
//     on hosts that block ICMP AND filter every probe port — fine.
func (s *Scanner) discoverHost(
	ctx context.Context, ip string, state *runState,
) (alive bool, methods []string, rtt time.Duration) {
	probeCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	type result struct {
		ok     bool
		via    string
		rttDur time.Duration
	}
	results := make(chan result, 3)

	// 1. Unprivileged ICMP.
	go func() {
		state.rates.take(ip)
		ok, d := pingICMP(probeCtx, ip)
		results <- result{ok, "icmp", d}
	}()

	// 2. TCP ping to 443 (HTTPS — universal-ish).
	go func() {
		state.rates.take(ip)
		ok, d := pingTCP(probeCtx, ip, 443, 1500*time.Millisecond)
		results <- result{ok, "tcp:443", d}
	}()

	// 3. TCP ping to 445 (SMB — every Windows + most NAS).
	go func() {
		state.rates.take(ip)
		ok, d := pingTCP(probeCtx, ip, 445, 1500*time.Millisecond)
		results <- result{ok, "tcp:445", d}
	}()

	// First positive wins; we don't need to wait for the other two
	// once we know the host is alive.
	collected := 0
	for collected < 3 {
		select {
		case r := <-results:
			collected++
			if r.ok {
				if rtt == 0 || r.rttDur < rtt {
					rtt = r.rttDur
				}
				methods = append(methods, r.via)
				// drain remaining in background to avoid leak
				go func() {
					for collected < 3 {
						<-results
						collected++
					}
				}()
				return true, methods, rtt
			}
		case <-probeCtx.Done():
			return false, nil, 0
		}
	}
	return false, nil, 0
}

// pingICMP sends one unprivileged ICMP echo. Returns (alive, RTT).
//
// We intentionally use Count=1 + short timeout: a sweep of a /24
// shouldn't take 4 seconds per host. Hosts that drop one packet under
// load look "dead" via ICMP but stage 1 still catches them via TCP.
func pingICMP(ctx context.Context, ip string) (bool, time.Duration) {
	p, err := probing.NewPinger(ip)
	if err != nil {
		return false, 0
	}
	// SetPrivileged(false) is the default — keep explicit for clarity
	// to future readers.
	p.SetPrivileged(false)
	p.Count = 1
	p.Timeout = 1500 * time.Millisecond

	var (
		mu  sync.Mutex
		rtt time.Duration
		ok  bool
	)
	p.OnRecv = func(pkt *probing.Packet) {
		mu.Lock()
		ok = true
		rtt = pkt.Rtt
		mu.Unlock()
	}
	// Honour ctx cancellation by stopping the pinger.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			p.Stop()
		case <-done:
		}
	}()
	_ = p.Run() // blocks until done or timeout
	close(done)
	mu.Lock()
	defer mu.Unlock()
	return ok, rtt
}

// pingTCP does a TCP SYN-and-close. Open or closed (RST) both count
// as alive — the only "no answer" outcome is filtered/dead.
func pingTCP(ctx context.Context, ip string, port int, timeout time.Duration) (bool, time.Duration) {
	d := net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	rtt := time.Since(start)
	if err == nil {
		_ = conn.Close()
		return true, rtt
	}
	// "connection refused" → host alive, port closed. The error text
	// varies by OS; checking via syscall would be cleaner but Go's
	// net.OpError string is stable enough for our needs.
	if ne, ok := err.(*net.OpError); ok && ne.Err != nil {
		s := ne.Err.Error()
		if containsAny(s, "refused", "reset by peer") {
			return true, rtt
		}
	}
	return false, 0
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) <= len(s) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
