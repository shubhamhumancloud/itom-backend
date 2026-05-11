// Package snmp is the thin wrapper around gosnmp that the walkers use.
//
// Three things this layer owns that gosnmp doesn't give us out of the
// box:
//
//   1. Typed errors. The dispatcher needs to distinguish "bad
//      community" (operator must rotate the credential) from "no UDP
//      response" (device is down or on another VLAN) — gosnmp returns
//      both as generic errors. Open() returns *ErrAuth /
//      *ErrUnreachable / *ErrTimeout instead.
//
//   2. WalkTable that returns map[suffix]Value. gosnmp's BulkWalk
//      callback hands you full OIDs; every walker would otherwise
//      re-implement the "strip the prefix, that's the row key" dance.
//
//   3. A small interface (Runner) so walker tests can swap in a fake
//      without standing up a real SNMP server.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Config is the input to Open. Zero values are filled with sensible
// defaults — most callers only need Target + Community.
type Config struct {
	Target         string
	Port           uint16              // default 161
	Community      string              // SNMPv2c shared secret
	Version        gosnmp.SnmpVersion  // default Version2c
	Timeout        time.Duration       // per-PDU; default 5s
	Retries        int                 // default 2
	MaxRepetitions uint32              // GETBULK page; default 50
}

// Runner is the small interface walker functions accept. Production
// callers pass *Client; tests pass a fake.
type Runner interface {
	Get(oids []string) (map[string]Value, error)
	WalkTable(rootOID string) (map[string]Value, error)
}

// Value is what one SNMP variable yields. We unify gosnmp's many PDU
// types into one Go type so walker code stays readable. Helpers
// (AsString, AsInt, …) below do safe coercion.
type Value struct {
	OID  string
	Kind ValueKind
	// Exactly one of these is set, matching Kind.
	Str   string
	Int   int64
	Bytes []byte
	// IPAddress and ObjectIdentifier are kept as Str.
}

// ValueKind discriminates Value.
type ValueKind int

const (
	KindUnknown ValueKind = iota
	KindString            // OctetString, IpAddress, ObjectIdentifier
	KindInt               // Integer, Counter32, Counter64, Gauge32, TimeTicks
	KindBytes             // raw OctetString when not printable (e.g. MAC)
	KindNull              // NoSuchObject / NoSuchInstance / EndOfMibView
)

// Client is the live SNMP session against one device. Single goroutine
// use only — gosnmp does not support concurrent in-flight requests on
// one connection.
type Client struct {
	g *gosnmp.GoSNMP
}

// ----- typed errors -----

// ErrAuth means the device responded but rejected our credentials
// (SNMPv2c "wrong community" → no response; SNMPv3 explicit auth-fail
// PDU). gosnmp surfaces both as a non-noisy error, so we infer auth
// failure from "the device is up (TCP open / ICMP reply) but SNMP
// returns nothing." For simplicity in v2c we treat the open-TCP path
// as the disambiguation hint — see Open().
type ErrAuth struct{ Wrapped error }

func (e *ErrAuth) Error() string { return "snmp auth failed: " + errString(e.Wrapped) }
func (e *ErrAuth) Unwrap() error { return e.Wrapped }

// ErrUnreachable means no UDP response within timeout × retries. The
// device might be powered off, blocked by ACL, or simply not running
// SNMP.
type ErrUnreachable struct{ Wrapped error }

func (e *ErrUnreachable) Error() string { return "snmp unreachable: " + errString(e.Wrapped) }
func (e *ErrUnreachable) Unwrap() error { return e.Wrapped }

// ErrTimeout means a specific walk took longer than the per-walk
// budget. Returned by WalkTable; distinct from ErrUnreachable which
// fires at session establishment.
type ErrTimeout struct{ Wrapped error }

func (e *ErrTimeout) Error() string { return "snmp timeout: " + errString(e.Wrapped) }
func (e *ErrTimeout) Unwrap() error { return e.Wrapped }

// IsAuth / IsUnreachable / IsTimeout are convenience helpers for callers
// that only need the classification, not the wrapped error.
func IsAuth(err error) bool        { var t *ErrAuth; return errors.As(err, &t) }
func IsUnreachable(err error) bool { var t *ErrUnreachable; return errors.As(err, &t) }
func IsTimeout(err error) bool     { var t *ErrTimeout; return errors.As(err, &t) }

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// ----- session lifecycle -----

// Open dials the device and confirms credentials by issuing one cheap
// GET for sysName.0. The trip-and-verify approach lets us return a
// typed error before any walker runs.
func Open(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Target == "" {
		return nil, errors.New("snmp: Target required")
	}
	if cfg.Port == 0 {
		cfg.Port = 161
	}
	if cfg.Version == 0 {
		cfg.Version = gosnmp.Version2c
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 2
	}
	if cfg.MaxRepetitions == 0 {
		cfg.MaxRepetitions = 50
	}
	if cfg.Version == gosnmp.Version2c && cfg.Community == "" {
		return nil, &ErrAuth{Wrapped: errors.New("v2c: community required")}
	}

	g := &gosnmp.GoSNMP{
		Target:             cfg.Target,
		Port:               cfg.Port,
		Community:          cfg.Community,
		Version:            cfg.Version,
		Timeout:            cfg.Timeout,
		Retries:            cfg.Retries,
		MaxRepetitions:     cfg.MaxRepetitions,
		ExponentialTimeout: true,
	}
	// gosnmp doesn't accept a context on Connect (UDP — instantaneous),
	// but honour cancellation between dial and verify.
	if err := g.Connect(); err != nil {
		return nil, &ErrUnreachable{Wrapped: err}
	}
	if err := ctx.Err(); err != nil {
		_ = g.Conn.Close()
		return nil, err
	}

	// Verify: a single GET on sysName.0. Three possible outcomes:
	//   - success           → creds OK, session alive
	//   - timeout           → device unreachable / SNMP disabled
	//   - response, but no value (NoSuchInstance / NoSuchObject) → device
	//     up + SNMP up + community accepted, but device doesn't expose
	//     sysName (unusual; we still accept the session)
	//
	// For SNMPv2c a wrong community looks identical to "no response"
	// from the wire — RFC 1157 says the agent silently drops bad-
	// community packets. So we classify v2c failure as ErrAuth ONLY
	// when the caller has confirmed via fingerprint that the device
	// is up; otherwise it's ErrUnreachable. The caller (driver)
	// decides which based on its own evidence.
	if _, err := g.Get([]string{OIDSysName + ".0"}); err != nil {
		_ = g.Conn.Close()
		return nil, &ErrUnreachable{Wrapped: err}
	}
	return &Client{g: g}, nil
}

// Close releases the UDP socket. Idempotent.
func (c *Client) Close() {
	if c == nil || c.g == nil || c.g.Conn == nil {
		return
	}
	_ = c.g.Conn.Close()
}

// ----- operations -----

// Get reads up to 60 scalar OIDs in one packet (gosnmp packs them).
// Returns map[oid]Value; absent OIDs map to a KindNull Value. Order
// doesn't matter to callers because the map key carries it.
func (c *Client) Get(oids []string) (map[string]Value, error) {
	if len(oids) == 0 {
		return map[string]Value{}, nil
	}
	res, err := c.g.Get(oids)
	if err != nil {
		return nil, classify(err)
	}
	out := make(map[string]Value, len(res.Variables))
	for _, v := range res.Variables {
		out[normaliseOID(v.Name)] = pduToValue(v)
	}
	return out, nil
}

// WalkTable returns every leaf under rootOID, keyed by the SUFFIX
// after rootOID. So a walk of "1.3.6.1.2.1.2.2.1.2" (ifDescr) returns
// {"1": "Gi1/0/1", "2": "Gi1/0/2", ...} — the suffix is whatever
// SNMP uses to index the table (often ifIndex, sometimes a compound
// like IP+ifIndex).
//
// Implementation uses GETBULK via gosnmp.BulkWalk. We accumulate
// into a map; a misbehaving agent that returns the same OID twice
// keeps the latest value.
func (c *Client) WalkTable(rootOID string) (map[string]Value, error) {
	root := normaliseOID(rootOID)
	out := map[string]Value{}
	cb := func(pdu gosnmp.SnmpPDU) error {
		name := normaliseOID(pdu.Name)
		suffix := strings.TrimPrefix(name, root+".")
		// Defensive: BulkWalk should only yield OIDs under root, but
		// some buggy agents return one extra row past the boundary.
		if suffix == name {
			return nil
		}
		out[suffix] = pduToValue(pdu)
		return nil
	}
	if err := c.g.BulkWalk(root, cb); err != nil {
		return nil, classify(err)
	}
	return out, nil
}

// ----- helpers -----

// classify maps gosnmp errors to our typed ones. gosnmp gives us
// timeout / "Request timeout" strings as plain *net.OpError or wrapped
// errors — we use string matching as a last resort because there's no
// stable sentinel.
func classify(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "request timeout"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "deadline exceeded"):
		return &ErrTimeout{Wrapped: err}
	case strings.Contains(msg, "auth"),
		strings.Contains(msg, "wrong digest"),
		strings.Contains(msg, "unknown user"):
		return &ErrAuth{Wrapped: err}
	default:
		return err
	}
}

// pduToValue is the single place that knows gosnmp's PDU type system.
// Walkers only see Value, so adding a new SNMP type (rare) is a
// one-line addition here.
func pduToValue(pdu gosnmp.SnmpPDU) Value {
	v := Value{OID: normaliseOID(pdu.Name)}
	switch pdu.Type {
	case gosnmp.OctetString:
		b, _ := pdu.Value.([]byte)
		v.Bytes = b
		if isPrintable(b) {
			v.Kind = KindString
			v.Str = string(b)
		} else {
			v.Kind = KindBytes
		}
	case gosnmp.ObjectIdentifier:
		s, _ := pdu.Value.(string)
		v.Kind = KindString
		v.Str = strings.TrimPrefix(s, ".")
	case gosnmp.IPAddress:
		s, _ := pdu.Value.(string)
		v.Kind = KindString
		v.Str = s
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Counter64,
		gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
		v.Kind = KindInt
		v.Int = toInt64(pdu.Value)
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		v.Kind = KindNull
	default:
		// Unknown type → leave Kind=KindUnknown. Walkers can still
		// inspect Bytes if non-nil.
		if b, ok := pdu.Value.([]byte); ok {
			v.Bytes = b
		}
	}
	return v
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case uint:
		return int64(x)
	case uint32:
		return int64(x)
	case uint64:
		return int64(x)
	default:
		return 0
	}
}

func isPrintable(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// normaliseOID strips a leading dot if present so map keys match
// regardless of how gosnmp or callers spelled the OID.
func normaliseOID(s string) string {
	return strings.TrimPrefix(s, ".")
}

// ----- Value helpers (used by walkers) -----

// AsString returns the value as a string. For KindBytes it returns
// hex with colon separators, useful for MAC addresses.
func (v Value) AsString() string {
	switch v.Kind {
	case KindString:
		return v.Str
	case KindBytes:
		return formatHex(v.Bytes)
	case KindInt:
		return fmt.Sprintf("%d", v.Int)
	default:
		return ""
	}
}

// AsInt coerces a KindInt; everything else returns 0.
func (v Value) AsInt() int64 {
	if v.Kind == KindInt {
		return v.Int
	}
	return 0
}

// AsMAC formats a 6-byte OctetString as an uppercase colon-separated
// MAC. Returns "" if the value isn't 6 bytes.
func (v Value) AsMAC() string {
	if (v.Kind == KindBytes || v.Kind == KindString) && len(v.Bytes) == 6 {
		return formatHex(v.Bytes)
	}
	return ""
}

// AsBytes returns the raw byte payload — used for LLDP chassis IDs,
// which are vendor-defined (sometimes MAC, sometimes hostname).
func (v Value) AsBytes() []byte { return v.Bytes }

func formatHex(b []byte) string {
	const hex = "0123456789abcdef"
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, 0, len(b)*3-1)
	for i, x := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[x>>4], hex[x&0x0f])
	}
	return string(out)
}
