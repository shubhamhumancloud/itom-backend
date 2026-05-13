import type { SampleDto } from '../../metrics/dto/create-metrics.dto';

/**
 * WebSocket protocol for agent ↔ server steady-state communication.
 *
 * Transport
 * ---------
 *  - Endpoint:  wss://<server>/v1/ws
 *  - Framing:   one JSON object per WebSocket text frame
 *  - Liveness:  WebSocket ping/pong every ~30s; missed pong → disconnect
 *
 * Lifecycle
 * ---------
 *  1. Agent registers ONCE via REST POST /v1/agents/register (bootstrap).
 *  2. Agent dials WS, sends `hello` as first message.
 *  3. Server replies `welcome` with the canonical agentId. If the backend
 *     reassigned the agent (fingerprint match to an existing record), the
 *     `agentId` in `welcome` differs from the one sent in `hello` and
 *     `reassigned: true`. The agent must adopt the canonical id.
 *  4. Agent streams `metrics` messages; server replies `ack` per requestId.
 *  5. On graceful shutdown agent sends `bye` and closes the socket.
 *
 * Why JSON envelopes
 * ------------------
 * Easy to debug (wscat, browser devtools). Can swap to binary/protobuf later
 * by adding a `Sec-WebSocket-Protocol` subprotocol negotiation — the message
 * shapes here become the .proto schema 1:1.
 *
 * IMPORTANT: this file MUST stay in sync with the Go agent's
 * `backend/agent/internal/wsproto/wsproto.go`. The two files are tiny and
 * hand-mirrored on purpose.
 */

// ---------- Client → Server ----------

export interface HelloMsg {
  type: 'hello';
  agentId: string;
  agentVersion: string;
  fingerprintHash?: string;
}

export interface MetricsMsg {
  type: 'metrics';
  requestId: string;
  samples: SampleDto[];
}

// Top processes — every 60 s. Best-effort, dropped if WS is down.
export interface ProcessesMsg {
  type: 'processes';
  requestId: string;
  timestamp: string;
  processes: ProcessSample[];
}
export interface ProcessSample {
  name: string;
  pidCount: number;
  cpuPercent: number;
  memoryBytes: number;
  ioReadBytes?: number;
  ioWriteBytes?: number;
}

// Battery — every 5 min, only emitted when a battery is present.
export interface BatteryMsg {
  type: 'battery';
  requestId: string;
  timestamp: string;
  percent: number;
  charging: boolean;
  onAC: boolean;
  cycleCount?: number;
  designCapacityMwh?: number;
  fullCapacityMwh?: number;
  healthPercent?: number;
  timeToFullSeconds?: number;
  timeToEmptySeconds?: number;
}

// CPU temperature + fan — every 60 s. Only readings the OS exposes.
export interface SensorsMsg {
  type: 'sensors';
  requestId: string;
  timestamp: string;
  readings: SensorReading[];
}
export interface SensorReading {
  name: string; // "Package id 0", "Core 1", "Fan1"
  kind: 'temperature_c' | 'fan_rpm';
  value: number;
}

// GPU — every 60 s. Inventory fields work on every platform; live metrics
// (util/mem/temp/power) are populated when a vendor tool is available
// (nvidia-smi, rocm-smi, powermetrics on Apple Silicon).
export interface GpuMsg {
  type: 'gpu';
  requestId: string;
  timestamp: string;
  gpus: GpuSample[];
}
export interface GpuSample {
  index: number;
  name: string;
  // 'nvidia' | 'amd' | 'intel' | 'apple' | 'qualcomm' | 'virtual' | 'unknown'
  vendor?: string;
  driverVersion?: string;
  // 'integrated' | 'discrete' | 'egpu' | 'virtual' | 'unknown'
  slotType?: string;
  utilizationPercent: number;
  memoryUsedBytes: number;
  memoryTotalBytes: number;
  temperatureC?: number;
  powerWatts?: number;
}

// Software inventory — once per 24 h. Full snapshot. Backend upserts.
export interface SoftwareInventoryMsg {
  type: 'software_inventory';
  requestId: string;
  timestamp: string;
  items: SoftwareItem[];
}
export interface SoftwareItem {
  name: string;
  version: string;
  publisher?: string;
  installedAt?: string; // ISO date
  sizeBytes?: number;
  source: 'msi' | 'dpkg' | 'rpm' | 'mac_app' | 'snap' | 'other';
}

export interface ByeMsg {
  type: 'bye';
}

export type ClientMsg =
  | HelloMsg
  | MetricsMsg
  | ProcessesMsg
  | BatteryMsg
  | SensorsMsg
  | GpuMsg
  | SoftwareInventoryMsg
  | ByeMsg;

// ---------- Server → Client ----------

export interface WelcomeMsg {
  type: 'welcome';
  agentId: string; // canonical (may differ from hello.agentId on reassignment)
  reassigned: boolean;
  heartbeatIntervalSeconds: number;
}

export type AckResult = 'committed' | 'duplicate' | 'rejected';

export interface AckMsg {
  type: 'ack';
  requestId: string;
  result: AckResult;
  message?: string;
}

export type ErrorCode =
  | 'auth_failed'
  | 'protocol_error'
  | 'unknown_agent'
  | 'internal_error';

export interface ErrorMsg {
  type: 'error';
  code: ErrorCode;
  message: string;
}

// Reserved for server-push (config changes, ad-hoc commands). Not yet emitted.
export interface ConfigUpdateMsg {
  type: 'config_update';
  intervalSeconds?: number;
}

export type ServerMsg = WelcomeMsg | AckMsg | ErrorMsg | ConfigUpdateMsg;

// 256 KB ceiling per frame. Catches runaway clients without rejecting honest
// large batches (60 samples × ~500 bytes = ~30 KB nominally; leave headroom).
export const MAX_FRAME_BYTES = 256 * 1024;
