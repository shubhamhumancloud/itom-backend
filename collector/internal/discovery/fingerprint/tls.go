package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// probeTLS does a TLS handshake against host:port, reads the leaf
// certificate, and returns subject + issuer as flattened DN strings
// (with SANs appended to the subject).
//
// We disable verification — appliance certs are almost always
// self-signed and we WANT to inspect them regardless of validity.
// Nothing here authenticates: we're just reading the public cert.
func probeTLS(ctx context.Context, host string, port int, timeout time.Duration) (subject, issuer string) {
	d := &net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rawConn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return "", ""
	}
	defer rawConn.Close()

	// Use a deadline for the TLS handshake itself; net/tls.Dialer
	// honours context but the handshake protocol still needs a clock
	// for old / broken devices that respond very slowly.
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true, // intentional — we're reading the cert, not trusting it
		ServerName:         host,
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return "", ""
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", ""
	}
	leaf := state.PeerCertificates[0]
	// Flatten subject + SANs into one comparable string so the scorer
	// can do plain `strings.Contains` checks.
	parts := []string{leaf.Subject.String()}
	if cn := leaf.Subject.CommonName; cn != "" {
		parts = append(parts, "CN="+cn)
	}
	for _, san := range leaf.DNSNames {
		parts = append(parts, "DNS:"+san)
	}
	for _, ou := range leaf.Subject.OrganizationalUnit {
		parts = append(parts, "OU="+ou)
	}
	for _, o := range leaf.Subject.Organization {
		parts = append(parts, "O="+o)
	}
	return strings.Join(parts, ", "), leaf.Issuer.String()
}
