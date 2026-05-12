package active

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// BannerInfo is what one banner grab learns about a port. Subsets are
// populated depending on the protocol — TLS ports get certificate
// details; SSH gets the version banner; HTTP gets the Server header.
type BannerInfo struct {
	Service     string
	Banner      string
	TLSCertCN   string
	TLSCertSANs []string
	TLSIssuer   string
}

// grabBanner dispatches to the right protocol prober based on port.
// We intentionally do NOT one-size-fits-all the request bytes — chapter
// 3 doc warns: "Don't send HTTP request bytes to port 22 — you'll just
// confuse a sensitive SSH server and might trigger fail2ban."
func grabBanner(ctx context.Context, ip string, port int) *BannerInfo {
	switch port {
	case 22:
		return grabSSH(ctx, ip, port)
	case 443, 8443, 993, 995, 465, 636, 989, 990:
		return grabTLS(ctx, ip, port)
	case 80, 8080, 81, 8081, 7547:
		return grabHTTP(ctx, ip, port)
	default:
		// For unknown ports we do a minimal "read first bytes" — many
		// chatty services (FTP, SMTP, MySQL, Redis) volunteer a banner
		// on connect. Never send anything; just listen briefly.
		return grabPassive(ctx, ip, port)
	}
}

// grabSSH reads the first line. RFC 4253 §4.2 mandates the server
// sends "SSH-2.0-..." as its first bytes, ending in CRLF.
func grabSSH(ctx context.Context, ip string, port int) *BannerInfo {
	conn, err := dial(ctx, ip, port, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReaderSize(conn, 256)
	line, err := r.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if err != nil && line == "" {
		return nil
	}
	return &BannerInfo{Service: "ssh", Banner: line}
}

// grabHTTP sends HTTP/1.0 with a Host header (some appliances respond
// 400 without it) and reads the first ~4KB.
func grabHTTP(ctx context.Context, ip string, port int) *BannerInfo {
	conn, err := dial(ctx, ip, port, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	req := "GET / HTTP/1.0\r\n" +
		"Host: " + ip + "\r\n" +
		"User-Agent: itom-collector\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _ := io.ReadFull(conn, buf)
	if n == 0 {
		return nil
	}
	resp := string(buf[:n])
	srv := extractHeader(resp, "Server")
	return &BannerInfo{
		Service: "http",
		Banner:  srv,
	}
}

// grabTLS does a TLS handshake and reads the leaf certificate. Subject
// CN and SubjectAltNames often expose internal hostnames (e.g.
// "*.corp.acme.com") that DNS would have hidden.
func grabTLS(ctx context.Context, ip string, port int) *BannerInfo {
	rawConn, err := dial(ctx, ip, port, 3*time.Second)
	if err != nil {
		return nil
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(4 * time.Second))

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ip,
	})
	defer tlsConn.Close()

	tlsCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(tlsCtx); err != nil {
		return nil
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	return &BannerInfo{
		Service:     "tls",
		Banner:      fmt.Sprintf("TLSv%s cipher=%s", tlsVersion(state.Version), tlsCipher(state.CipherSuite)),
		TLSCertCN:   leaf.Subject.CommonName,
		TLSCertSANs: leaf.DNSNames,
		TLSIssuer:   leaf.Issuer.String(),
	}
}

// grabPassive just listens for the first bytes a service might
// volunteer on connect. Examples:
//   FTP:    "220 (vsFTPd 3.0.3)"
//   SMTP:   "220 mail.example.com ESMTP Postfix"
//   MySQL:  binary handshake — non-printable but identifies as "mysql"
//   Redis:  silent — we get nothing, return nil
func grabPassive(ctx context.Context, ip string, port int) *BannerInfo {
	conn, err := dial(ctx, ip, port, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil
	}
	return &BannerInfo{
		Service: classifyBytes(buf[:n]),
		Banner:  printable(buf[:n]),
	}
}

// classifyBytes makes a coarse service guess from the first few bytes.
// We don't try to be clever — just enough to label the open_port row
// with something useful when the protocol-specific grabber didn't fire.
func classifyBytes(b []byte) string {
	s := string(b)
	switch {
	case strings.HasPrefix(s, "SSH-"):
		return "ssh"
	case strings.HasPrefix(s, "HTTP/"):
		return "http"
	case strings.HasPrefix(s, "220 ") && strings.Contains(s, "FTP"):
		return "ftp"
	case strings.HasPrefix(s, "220 ") && strings.Contains(s, "ESMTP"):
		return "smtp"
	case strings.HasPrefix(s, "220 ") && strings.Contains(s, "SMTP"):
		return "smtp"
	case strings.HasPrefix(s, "+OK"):
		return "pop3"
	case strings.HasPrefix(s, "* OK"):
		return "imap"
	case len(b) > 4 && b[0] >= 5 && b[0] <= 15 && b[1] == 0 && b[2] == 0 && b[3] == 0:
		// MySQL handshake: 4-byte length prefix followed by version 10.
		if len(b) > 5 && b[4] == 0x0a {
			return "mysql"
		}
	}
	return "unknown"
}

// printable returns the input as a string with non-printable bytes
// replaced by '.', and capped at 200 chars so we don't pollute the
// observation with a kilobyte of binary.
func printable(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x20 && c < 0x7f {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func dial(ctx context.Context, ip string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", ip, port))
}

// extractHeader pulls a header line from an HTTP response string.
// Cheap and forgiving — won't blow up on malformed responses (we'd
// rather miss the Server header than fail the whole banner grab).
func extractHeader(resp, key string) string {
	needle := strings.ToLower(key) + ":"
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		l := strings.ToLower(line)
		if strings.HasPrefix(l, needle) {
			return strings.TrimSpace(line[len(needle):])
		}
	}
	return ""
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "?"
	}
}

func tlsCipher(c uint16) string {
	if name := tls.CipherSuiteName(c); name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", c)
}
