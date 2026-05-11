// Package wsproto declares the WebSocket frames the collector exchanges
// with the backend during a discovery scan-job lifecycle. Mirrors
// backend/BE/src/discovery/ws/protocol.ts byte-for-byte.
//
// Each text frame is one JSON object with `kind` and `payload`. We
// follow this two-level pattern (rather than a flat `type` field like
// the agent uses) because discovery payloads are larger and more
// strongly typed, and the kind-first shape makes peek-and-route trivial.
package wsproto

import (
	"encoding/json"
	"fmt"
)

// FrameKind discriminates the payload inside Frame.
type FrameKind string

// ----- shared envelope kinds -----
const (
	// Collector → server: first frame after the WS handshake.
	KindHello FrameKind = "hello"
	// Server → collector: acknowledges hello, may correct collectorId.
	KindWelcome FrameKind = "welcome"
	// Server → collector: terminal auth/protocol failure; socket closes.
	KindError FrameKind = "error"
	// Server → collector: lightweight ping outside the WS ping/pong so
	// the BE can attach a request-id and the collector can echo it back.
	KindPing FrameKind = "ping"
	// Collector → server: response to KindPing.
	KindPong FrameKind = "pong"
)

// ----- scan-job kinds -----
const (
	KindScanJobAssign FrameKind = "scan_job.assign"
	KindScanJobAck    FrameKind = "scan_job.ack"
	KindScanJobChunk  FrameKind = "scan_job.chunk"
	KindScanJobDone   FrameKind = "scan_job.done"
	KindScanJobError  FrameKind = "scan_job.error"
)

// Frame is the on-the-wire envelope.
type Frame struct {
	Kind    FrameKind       `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

// NewFrame marshals v into Payload and returns a Frame.
func NewFrame(kind FrameKind, v any) (Frame, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Frame{}, fmt.Errorf("wsproto: marshal %s payload: %w", kind, err)
	}
	return Frame{Kind: kind, Payload: raw}, nil
}

// Decode unmarshals f.Payload into dst.
func (f Frame) Decode(dst any) error {
	return json.Unmarshal(f.Payload, dst)
}

// ----- hello / welcome -----

// Hello — collector to server. Sent as the first frame after dialing
// /v1/discovery/ws. The server validates collectorId + tenantId,
// promotes the socket from `pending` to `connections`, and replies
// with Welcome.
type Hello struct {
	CollectorID string `json:"collectorId"`
	TenantID    string `json:"tenantId"`
	Version     string `json:"version"`
	// Role pins this socket to the discovery surface; the BE rejects
	// host-metrics frames on /v1/discovery/ws and vice versa.
	Role string `json:"role"` // always "collector"
}

// Welcome — server to collector. Carries the canonical collectorId in
// case fingerprint reconciliation rewrote it, and the heartbeat cadence
// the collector should expect.
type Welcome struct {
	CollectorID              string `json:"collectorId"`
	Reassigned               bool   `json:"reassigned"`
	HeartbeatIntervalSeconds int    `json:"heartbeatIntervalSeconds"`
}

// Error — server to collector. Terminal; the socket closes after this.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Ping/Pong — application-level liveness; carries request id.
type Ping struct {
	RequestID string `json:"requestId"`
}
type Pong struct {
	RequestID string `json:"requestId"`
}

// ----- scan job -----

// ScanJobAssign — server to collector. Pushed when a row is inserted
// into disc_scan_job targeted at this collector. Contains everything the
// collector needs to run the job — including the signed CIDR allowlist
// and credential references the collector requests JIT.
type ScanJobAssign struct {
	JobID         string         `json:"jobId"`
	SessionID     string         `json:"sessionId"`
	TenantID      string         `json:"tenantId"`
	Pillar        string         `json:"pillar"`     // "firewall" | "snmp" | "active" | "noop"
	Vendor        string         `json:"vendor"`     // for pillar=firewall: "fortigate" | "paloalto" | …
	TargetSpec    map[string]any `json:"targetSpec"` // free-form per-pillar (host, vdoms, etc.)
	CredentialIDs []string       `json:"credentialIds"`
	// AllowlistCIDRs is the list the collector must enforce on every
	// target IP it touches. Signed with AllowlistSignature.
	AllowlistCIDRs     []string `json:"allowlistCidrs"`
	AllowlistSignature string   `json:"allowlistSignature"` // base64 Ed25519
}

// ScanJobAck — collector to server. "Got it, starting."
type ScanJobAck struct {
	JobID       string `json:"jobId"`
	CollectorID string `json:"collectorId"`
	AcceptedAt  string `json:"acceptedAt"` // RFC3339
}

// ScanJobChunk — collector to server. A batch of observations,
// NDJSON-style. Backend appends them to the session keyed by SessionID.
type ScanJobChunk struct {
	JobID        string        `json:"jobId"`
	SessionID    string        `json:"sessionId"`
	Observations []Observation `json:"observations"`
	// Cursor is opaque pillar-specific paging state for long-running
	// crawls. Firewall ingest doesn't use it (single pass per context).
	Cursor map[string]any `json:"cursor,omitempty"`
}

// Observation matches disc_observation in backend/BE.
//
// SubjectKey conventions live with the pillar that produces them — see
// internal/discovery/firewall/observations.go for the firewall scheme.
type Observation struct {
	SubjectKind string `json:"subjectKind"`
	SubjectKey  string `json:"subjectKey"`
	Attribute   string `json:"attribute"`
	Value       any    `json:"value"`
	SeenAt      string `json:"seenAt"` // RFC3339
}

// ScanJobDone — collector to server. Signals normal completion.
type ScanJobDone struct {
	JobID            string `json:"jobId"`
	SessionID        string `json:"sessionId"`
	ObservationCount int    `json:"observationCount"`
	EndedAt          string `json:"endedAt"` // RFC3339
}

// ScanJobError — collector to server. Signals abnormal completion.
// Backend records the reason and surfaces it on the dashboard.
type ScanJobError struct {
	JobID  string `json:"jobId"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}
