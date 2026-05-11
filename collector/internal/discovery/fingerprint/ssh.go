package fingerprint

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// probeSSHBanner does a TCP connect to host:22, reads the SSH greeting
// (first text line, ending in CRLF), and returns it. No SSH handshake
// is performed — we never authenticate. Banners look like:
//
//	SSH-2.0-OpenSSH_8.4
//	SSH-2.0-Cisco-1.25
//	SSH-2.0-mpSSH_0.2.1                (Palo Alto)
//	SSH-2.0-FortiSSH_1.0               (FortiGate)
//	SSH-2.0-Comware-7.1.045            (HPE / H3C)
//
// The banner is the strongest "free" signal — even devices that hide
// every other detail leak it because RFC 4253 mandates it.
func probeSSHBanner(ctx context.Context, host string, timeout time.Duration) string {
	d := net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", host, 22))
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	// Banner is one line, well under a kilobyte. Cap the read so a
	// malicious peer can't make us read forever.
	r := bufio.NewReaderSize(conn, 512)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "SSH-") {
		// Not a real SSH service — skip.
		return ""
	}
	return line
}
