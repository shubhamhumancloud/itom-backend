package fingerprint

import (
	"context"
	"fmt"
	"net"
	"time"
)

// scanTCPPorts attempts a TCP connect to each port and returns those
// that accept the SYN+ACK within timeout. We don't send any data —
// the connection is closed immediately — so the only side-effect on
// the target is a short-lived half-open socket, no logged auth
// failures.
//
// We deliberately do NOT scan UDP (e.g. 161 for SNMP) from this
// function. UDP "openness" requires sending a service-specific probe
// and parsing the reply; we handle that in the SNMP probe directly.
func scanTCPPorts(ctx context.Context, host string, ports []int, timeout time.Duration) []int {
	open := make([]int, 0, len(ports))
	for _, p := range ports {
		if p == 161 {
			// UDP-only service; skip in TCP scan, the SNMP probe handles it.
			continue
		}
		if ctx.Err() != nil {
			return open
		}
		if tcpConnects(ctx, host, p, timeout) {
			open = append(open, p)
		}
	}
	return open
}

func tcpConnects(ctx context.Context, host string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
