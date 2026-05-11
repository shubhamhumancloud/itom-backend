// Package cidrguard enforces the per-tenant CIDR allowlist on every
// target IP / host the collector touches. The allowlist arrives with
// each scan-job assignment, signed by the BE with Ed25519. The collector
// holds the BE's public key (loaded from config) and refuses any
// assignment whose signature doesn't verify.
//
// Why sign? Defence in depth. A bug or compromise on the BE that sends
// the wrong CIDR list must NOT make the collector scan Acme's
// competitor. The signature pins the list to "the real BE said this".
package cidrguard

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Guard wraps a parsed, signature-verified allowlist.
type Guard struct {
	cidrs []netip.Prefix
}

// New returns a Guard from a list of CIDRs (no signature). Returns an
// error on the first malformed entry — refuse to start a scan rather
// than silently dropping one and scanning more than intended.
//
// Use VerifyAndLoad in production. New is fine for unit tests and the
// local `noop` simulator path.
func New(cidrs []string) (*Guard, error) {
	g := &Guard{cidrs: make([]netip.Prefix, 0, len(cidrs))}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("cidr %q: %w", c, err)
		}
		g.cidrs = append(g.cidrs, p)
	}
	return g, nil
}

// VerifyAndLoad parses, signature-verifies, and loads the CIDR allowlist.
//
//   - publicKey: the BE's Ed25519 public key (32 bytes). Bake into the
//     collector binary at install time, same channel as serverURL.
//   - cidrs:     the list as it arrived in the ScanJobAssign frame.
//   - signature: base64-encoded Ed25519 signature over the canonical
//     serialisation (see CanonicalBytes).
//
// Returns an error if the signature does not verify; the dispatcher
// must then reply with ScanJobError and write an audit row.
func VerifyAndLoad(publicKey ed25519.PublicKey, cidrs []string, signature string) (*Guard, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("cidrguard: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(publicKey))
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return nil, fmt.Errorf("cidrguard: signature not base64: %w", err)
	}
	msg, err := CanonicalBytes(cidrs)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(publicKey, msg, sig) {
		return nil, errors.New("cidrguard: signature did not verify")
	}
	return New(cidrs)
}

// CanonicalBytes returns the deterministic byte sequence the BE signs
// over. Two collectors with the same allowlist must produce the same
// bytes, so we sort + JSON-encode under a fixed shape:
//
//	{"v":1,"cidrs":["10.0.0.0/8","192.168.1.0/24"]}
//
// The BE produces identical bytes when signing in signing.service.ts.
func CanonicalBytes(cidrs []string) ([]byte, error) {
	cp := make([]string, len(cidrs))
	copy(cp, cidrs)
	sort.Strings(cp)
	type canonical struct {
		Version int      `json:"v"`
		CIDRs   []string `json:"cidrs"`
	}
	return json.Marshal(canonical{Version: 1, CIDRs: cp})
}

// Allow reports whether the IP (v4 or v6) sits inside any of the
// allowlisted CIDRs. An empty allowlist always denies — never
// default-allow.
func (g *Guard) Allow(ip net.IP) bool {
	if g == nil || len(g.cidrs) == 0 {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip.To16())
	if !ok {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, p := range g.cidrs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// AllowString is a convenience for string-IP callers.
func (g *Guard) AllowString(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return g.Allow(ip)
}

// CIDRs returns a copy of the loaded allowlist as strings — handy for
// logging the resolved scope on job start without exposing the netip
// type to callers.
func (g *Guard) CIDRs() []string {
	if g == nil {
		return nil
	}
	out := make([]string, 0, len(g.cidrs))
	for _, p := range g.cidrs {
		out = append(out, p.String())
	}
	return out
}
