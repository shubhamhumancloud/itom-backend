/**
 * Discovery WebSocket protocol — must stay byte-for-byte in sync with
 * backend/collector/internal/wsproto/wsproto.go.
 *
 * Each text frame is one JSON object with `kind` and `payload`. We
 * follow this two-level pattern (rather than the agent's flat `type`
 * field) because discovery payloads are larger and more strongly
 * typed, and the kind-first shape makes peek-and-route trivial on
 * both sides.
 */

export type FrameKind =
  // shared envelope
  | 'hello'
  | 'welcome'
  | 'error'
  | 'ping'
  | 'pong'
  // scan job
  | 'scan_job.assign'
  | 'scan_job.ack'
  | 'scan_job.chunk'
  | 'scan_job.done'
  | 'scan_job.error';

export interface Frame<P = unknown> {
  kind: FrameKind;
  payload: P;
}

// ---------- hello / welcome ----------

export interface HelloPayload {
  collectorId: string;
  tenantId: string;
  version: string;
  role: 'collector';
}

export interface WelcomePayload {
  collectorId: string;
  reassigned: boolean;
  heartbeatIntervalSeconds: number;
}

export type ErrorCode =
  | 'auth_failed'
  | 'protocol_error'
  | 'unknown_collector'
  | 'internal_error';

export interface ErrorPayload {
  code: ErrorCode;
  message: string;
}

export interface PingPayload {
  requestId: string;
}
export interface PongPayload {
  requestId: string;
}

// ---------- scan job ----------

export interface ScanJobAssignPayload {
  jobId: string;
  sessionId: string;
  tenantId: string;
  pillar: 'noop' | 'firewall' | 'snmp' | 'active';
  vendor?: 'fortigate' | 'paloalto' | 'checkpoint' | 'cisco_asa' | '';
  targetSpec: Record<string, unknown>;
  credentialIds: string[];
  allowlistCidrs: string[];
  allowlistSignature: string; // base64 Ed25519 over canonicalAllowlist(allowlistCidrs)
}

export interface ScanJobAckPayload {
  jobId: string;
  collectorId: string;
  acceptedAt: string; // RFC3339
}

export interface ObservationPayload {
  subjectKind: string;
  subjectKey: string;
  attribute: string;
  value: unknown;
  seenAt: string; // RFC3339
}

export interface ScanJobChunkPayload {
  jobId: string;
  sessionId: string;
  observations: ObservationPayload[];
  cursor?: Record<string, unknown>;
}

export interface ScanJobDonePayload {
  jobId: string;
  sessionId: string;
  observationCount: number;
  endedAt: string; // RFC3339
}

export interface ScanJobErrorPayload {
  jobId: string;
  reason: string;
  detail?: string;
}

// 1 MiB per frame. Discovery chunks are bigger than host-metrics
// batches (firewall configs can be sizeable), but a 1 MiB ceiling is
// still well below WS implementation limits and catches runaway
// chunks before they crush the BE.
export const DISCOVERY_MAX_FRAME_BYTES = 1 * 1024 * 1024;
