// Package device defines the vendor-agnostic Driver contract the
// crawl loop calls against every discovered device, plus the small
// shared value types (Creds, NeighbourHint, Fingerprint references) it
// needs.
//
// Why is this separate from `firewall.Ingestor`? Because not every
// device is a firewall. A switch, an L3 router, a generic SNMP target,
// or a wireless controller all need to be drivable from the same
// crawl loop, and forcing them through a firewall-shaped interface
// (with NAT rules and IPsec tunnels) is the wrong shape.
//
// A firewall driver wraps a `firewall.Ingestor` and adapts it to this
// interface. A future SNMP-only driver will satisfy this interface
// directly without going through `firewall.Ingestor` at all.
package device

import (
	"context"

	"github.com/itom-mini/collector/internal/wsproto"
)

// Vendor enumerates the device families we have (or plan to have)
// drivers for. The string values are the same ones used in
// ScanJobAssign.vendor / driver registry keys.
type Vendor string

const (
	VendorUnknown    Vendor = ""
	VendorFortiGate  Vendor = "fortigate"
	VendorPaloAlto   Vendor = "paloalto"
	VendorCheckPoint Vendor = "checkpoint"
	VendorCiscoASA   Vendor = "cisco_asa"
	VendorCiscoIOS   Vendor = "cisco_ios"
	VendorJuniperOS  Vendor = "juniper_junos"
	VendorGenericSNMP Vendor = "generic_snmp"
)

// Creds is the union of every authentication shape any driver might
// need. Drivers pick the fields they care about; the rest stay zero.
//
// Kept here (not in `firewall.Creds`) so SNMP-only drivers don't have
// to import the firewall package.
type Creds struct {
	Host                 string
	Username             string
	Password             string
	APIKey               string
	TLSFingerprintSHA256 string
	// SNMPv2c community. Empty means "no v2c credential" — but the SNMPv3
	// fields below may still be populated for a v3-only device.
	SNMPCommunity string
	// SNMPv3 USM parameters. SNMPv3Username being non-empty switches
	// the SNMP driver/fingerprint probe into v3 mode.
	SNMPv3Username     string
	SNMPv3AuthProtocol string // "sha" | "sha256" | "sha512" | "md5" | ""
	SNMPv3AuthKey      string
	SNMPv3PrivProtocol string // "aes" | "aes192" | "aes256" | "des" | ""
	SNMPv3PrivKey      string
}

// HasSNMP returns true if either v2c community or v3 username is set.
// Used by the fingerprint probe and the generic_snmp driver to know
// whether SNMP credentials were supplied at all.
func (c Creds) HasSNMP() bool {
	return c.SNMPCommunity != "" || c.SNMPv3Username != ""
}

// Fingerprint is the evidence + best-guess output of the identify
// probes. Stored alongside the device so a future re-crawl can see
// what classification was used. (We don't persist this yet; it rides
// the in-memory crawl state for now.)
type Fingerprint struct {
	Vendor     Vendor
	Confidence Confidence

	OpenTCPPorts []int  // result of the port-shape probe
	TLSSubject   string // CN+SAN of the leaf certificate
	TLSIssuer    string
	HTTPServer   string // value of `Server:` header from /
	SSHBanner    string // first line of SSH greeting
	SysObjectID  string // SNMP sysObjectID OID (chapter-2 wiring)

	// Reasons is a short human-readable list of which probes
	// contributed to the verdict. Useful in audit logs and dashboards.
	Reasons []string
}

// Confidence is the qualitative trust level for the fingerprint. We
// keep it ordinal-but-small so callers can branch on it cheaply.
type Confidence int

const (
	ConfidenceNone Confidence = iota
	ConfidenceLow
	ConfidenceMedium
	ConfidenceHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceHigh:
		return "high"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceLow:
		return "low"
	default:
		return "none"
	}
}

// NeighbourHint is one address the crawl loop should consider visiting
// next. The Reason explains where we got it so the audit log + dashboard
// can show "Pune-router was discovered because HQ-firewall said it's
// its BGP peer."
type NeighbourHint struct {
	IP     string
	Reason string // e.g. "bgp_peer", "ospf_peer", "route_next_hop", "vpn_peer", "arp"
	// Hint may carry an optional vendor guess (e.g. the source firewall
	// reported `protocol=cisco` for a routing peer). Empty means the
	// crawl runs the full fingerprint ladder.
	VendorHint Vendor
}

// IngestResult bundles everything a Driver produces in one Ingest call.
// Returning them together (rather than streaming) keeps the Driver
// interface simple; the crawl loop is the one that batches into
// ScanJobChunk frames.
//
// ChassisID is the authoritative identity of the device — chassis
// serial preferred, falls back to LLDP local chassis ID, finally to
// sysName. The crawler uses it for dedup so a 5-IP router isn't
// walked 5 times. Empty means "couldn't determine identity"; the
// crawler falls back to IP-only dedup for that row.
type IngestResult struct {
	Observations []wsproto.Observation
	Neighbours   []NeighbourHint
	ChassisID    string
}

// ErrAuth signals the device responded but rejected our credential.
// Distinct from ErrUnreachable so the operator knows to rotate a
// credential vs. fix routing / firewalling.
type ErrAuth struct{ Wrapped error }

func (e *ErrAuth) Error() string { return "device auth failed: " + errString(e.Wrapped) }
func (e *ErrAuth) Unwrap() error { return e.Wrapped }

// ErrUnreachable signals the device did not respond at all on the
// management protocol we tried.
type ErrUnreachable struct{ Wrapped error }

func (e *ErrUnreachable) Error() string {
	return "device unreachable: " + errString(e.Wrapped)
}
func (e *ErrUnreachable) Unwrap() error { return e.Wrapped }

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// Driver is the contract every vendor implementation satisfies. One
// Driver instance handles one device for one Ingest call — the crawl
// loop builds a fresh Driver per device via the registry, so drivers
// can hold per-device session state (auth cookies, etc.) without
// concurrency concerns.
type Driver interface {
	// Vendor reports which vendor this driver claims to handle. The
	// registry uses this for the reverse lookup; the crawl loop logs
	// it onto every emitted observation as provenance.
	Vendor() Vendor

	// Ingest authenticates, pulls whatever this driver supports against
	// the device at creds.Host, and returns both the observations and
	// the neighbour hints to feed back into the crawl queue.
	//
	// Ingest must respect ctx cancellation; the dispatcher cancels on
	// disconnect.
	Ingest(ctx context.Context, creds Creds) (IngestResult, error)
}

// Factory constructs a fresh Driver. Used by the registry so drivers
// can have constructor-time wiring (loggers, timeouts) without the
// crawl loop knowing about it.
type Factory func() Driver
