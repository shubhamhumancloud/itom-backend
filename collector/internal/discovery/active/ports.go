package active

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// scanPorts is stage 2. Worker pool of (capped) goroutines does
// TCP connects across the requested port list. Returns the sorted
// list of ports that accepted the connection.
//
// We use TCP connect (full handshake) rather than SYN scan because:
//   (a) it works without raw-socket privileges on every OS,
//   (b) "open" is unambiguous — we ONLY accept a port if the kernel
//       completed the 3-way handshake, no false positives,
//   (c) the cost difference vs SYN scan is marginal at the rate caps
//       chapter 3 mandates (~1000 PPS/subnet).
const portWorkers = 32

func (s *Scanner) scanPorts(ctx context.Context, ip string, ports []int, state *runState) []int {
	type result struct {
		port int
		open bool
	}
	results := make(chan result, len(ports))
	sem := make(chan struct{}, portWorkers)
	var wg sync.WaitGroup

	for _, p := range ports {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			state.rates.take(ip)
			results <- result{port, tcpConnect(ctx, ip, port, 2*time.Second)}
		}(p)
	}
	wg.Wait()
	close(results)

	open := make([]int, 0, 8)
	for r := range results {
		if r.open {
			open = append(open, r.port)
		}
	}
	sort.Ints(open)
	return open
}

func tcpConnect(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
