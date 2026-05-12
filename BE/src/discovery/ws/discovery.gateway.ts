import { Logger, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { IncomingMessage } from 'http';
import { WebSocket, WebSocketServer as WSServer } from 'ws';
import { CollectorService } from '../collector.service';
import { ObservationIngestService } from '../observation-ingest.service';
import { ScanJobService } from '../scan-job.service';
import { AuditLogService } from '../audit-log.service';
import { FusionService } from '../fusion/fusion.service';
import {
  DISCOVERY_MAX_FRAME_BYTES,
  ErrorPayload,
  Frame,
  HelloPayload,
  ScanJobAckPayload,
  ScanJobAssignPayload,
  ScanJobChunkPayload,
  ScanJobDonePayload,
  ScanJobErrorPayload,
  WelcomePayload,
} from './protocol';

/**
 * Collector ↔ server WebSocket. Path is `/v1/discovery/ws`, distinct
 * from the agent's `/v1/ws` so the two surfaces never accidentally
 * share frame shapes. Lifecycle mirrors the agent gateway:
 *
 *   1. Collector dials → `pending` until hello.
 *   2. Hello carries collectorId + tenantId + token (Sec-WebSocket-Protocol).
 *      Validate, mark collector online, promote to `connections`, send Welcome.
 *   3. Stream `scan_job.ack` / `scan_job.chunk` / `scan_job.done` /
 *      `scan_job.error` from the collector. The server-side push of
 *      `scan_job.assign` is driven by the scan-job dispatcher service
 *      via `sendTo(collectorId, frame)`.
 *
 * Auth note: the WS handshake itself doesn't carry HTTP headers
 * portably across all websocket clients, so we accept the bearer in
 * the `Sec-WebSocket-Protocol` subprotocol header (a widely-used
 * convention — gorilla/websocket and `ws` both pass it through).
 * Format: `itom-collector-token.<bearer>`.
 */
@WebSocketGateway({
  path: '/v1/discovery/ws',
  maxPayload: DISCOVERY_MAX_FRAME_BYTES,
})
export class DiscoveryGateway
  implements OnGatewayConnection, OnGatewayDisconnect, OnModuleInit
{
  private readonly logger = new Logger(DiscoveryGateway.name);
  private readonly heartbeatIntervalMs = 30_000;
  private heartbeatTimer?: NodeJS.Timeout;

  /** collectorId → live socket. Populated only after a successful hello. */
  private readonly connections = new Map<string, WebSocket>();
  /** Pending sockets (pre-hello). */
  private readonly pending = new WeakMap<
    WebSocket,
    { connectedAt: number; remoteAddr: string; bearer: string }
  >();
  private readonly alive = new WeakSet<WebSocket>();

  @WebSocketServer()
  private readonly server!: WSServer;

  constructor(
    private readonly collectors: CollectorService,
    private readonly observations: ObservationIngestService,
    private readonly jobs: ScanJobService,
    private readonly audit: AuditLogService,
    private readonly fusion: FusionService,
  ) {}

  onModuleInit() {
    this.heartbeatTimer = setInterval(() => {
      for (const ws of this.server?.clients ?? []) {
        if (!this.alive.has(ws)) {
          this.logger.warn('terminating unresponsive collector socket');
          ws.terminate();
          continue;
        }
        this.alive.delete(ws);
        try {
          ws.ping();
        } catch (e: any) {
          this.logger.warn(`ping failed: ${e.message}`);
        }
      }
    }, this.heartbeatIntervalMs);
  }

  handleConnection(ws: WebSocket, req: IncomingMessage) {
    const remoteAddr =
      (req.headers['x-forwarded-for'] as string) ?? req.socket.remoteAddress ?? 'unknown';
    const bearer = extractBearerFromHandshake(req);
    this.pending.set(ws, { connectedAt: Date.now(), remoteAddr, bearer });
    this.alive.add(ws);
    ws.on('pong', () => this.alive.add(ws));
    ws.on('message', (data) => this.onMessage(ws, data.toString()));
    ws.on('error', (err) => this.logger.warn(`socket error: ${err.message}`));
    this.logger.log(`collector socket connected from ${remoteAddr}`);
  }

  handleDisconnect(ws: WebSocket) {
    const collectorId = this.findCollectorId(ws);
    if (collectorId) {
      this.connections.delete(collectorId);
      this.collectors.markOffline(collectorId).catch((e) =>
        this.logger.warn(`markOffline ${collectorId} failed: ${e.message}`),
      );
      this.logger.log(`collector disconnected collectorId=${collectorId}`);
    } else {
      this.logger.log('pending collector socket disconnected before hello');
    }
  }

  // -----------------------------------------------------------------
  // Server-push API (used by scan-job dispatcher to send to a collector)
  // -----------------------------------------------------------------

  /** Push a frame to a connected collector. Returns false if not connected. */
  sendTo(collectorId: string, frame: Frame): boolean {
    const ws = this.connections.get(collectorId);
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    ws.send(JSON.stringify(frame));
    return true;
  }

  /** True if a collector has an active session. */
  isConnected(collectorId: string): boolean {
    const ws = this.connections.get(collectorId);
    return !!ws && ws.readyState === WebSocket.OPEN;
  }

  // -----------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------

  private async onMessage(ws: WebSocket, raw: string) {
    let frame: Frame;
    try {
      frame = JSON.parse(raw) as Frame;
    } catch {
      return this.fail(ws, 'protocol_error', 'malformed JSON');
    }
    if (!frame || typeof frame !== 'object' || !('kind' in frame)) {
      return this.fail(ws, 'protocol_error', 'missing kind');
    }
    switch (frame.kind) {
      case 'hello':
        return this.onHello(ws, frame.payload as HelloPayload);
      case 'pong':
        // alive set is updated by the WS-level pong handler too; this
        // application-level pong is a redundant signal we accept silently.
        return;
      case 'scan_job.ack':
        return this.onAck(ws, frame.payload as ScanJobAckPayload);
      case 'scan_job.chunk':
        return this.onChunk(ws, frame.payload as ScanJobChunkPayload);
      case 'scan_job.done':
        return this.onDone(ws, frame.payload as ScanJobDonePayload);
      case 'scan_job.error':
        return this.onError(ws, frame.payload as ScanJobErrorPayload);
      default:
        return this.fail(ws, 'protocol_error', `unknown kind: ${frame.kind}`);
    }
  }

  private async onHello(ws: WebSocket, msg: HelloPayload) {
    if (this.findCollectorId(ws)) {
      return this.fail(ws, 'protocol_error', 'hello already received');
    }
    if (!msg?.collectorId || !msg?.tenantId || msg?.role !== 'collector') {
      return this.fail(ws, 'protocol_error', 'hello missing fields or wrong role');
    }
    const pend = this.pending.get(ws);
    if (!pend) return this.fail(ws, 'protocol_error', 'no pending state');

    try {
      const row = await this.collectors.verifyToken(msg.collectorId, pend.bearer);
      if (row.tenantId !== msg.tenantId) {
        throw new UnauthorizedException('tenant mismatch');
      }
      // Promote socket
      this.pending.delete(ws);
      const prev = this.connections.get(row.id);
      if (prev && prev !== ws) {
        this.logger.warn(`replacing stale socket for collector ${row.id}`);
        try {
          prev.close(1000, 'replaced by newer connection');
        } catch {
          /* noop */
        }
      }
      this.connections.set(row.id, ws);
      await this.collectors.markOnline(row.id, msg.version || null);

      const welcome: Frame<WelcomePayload> = {
        kind: 'welcome',
        payload: {
          collectorId: row.id,
          reassigned: false,
          heartbeatIntervalSeconds: this.heartbeatIntervalMs / 1000,
        },
      };
      ws.send(JSON.stringify(welcome));
      this.logger.log(
        `collector online collectorId=${row.id} tenantId=${row.tenantId} version=${msg.version}`,
      );
    } catch (e: any) {
      await this.audit
        .write({
          tenantId: msg.tenantId,
          actor: `collector:${msg.collectorId}`,
          action: 'collector.auth_failed',
          metadata: { reason: e.message ?? 'unknown' },
        })
        .catch(() => undefined);
      return this.fail(ws, 'auth_failed', e.message ?? 'auth failed');
    }
  }

  private async onAck(ws: WebSocket, msg: ScanJobAckPayload) {
    const collectorId = this.findCollectorId(ws);
    if (!collectorId) return this.fail(ws, 'protocol_error', 'ack before hello');
    await this.jobs.markRunning(msg.jobId, collectorId).catch((e) =>
      this.logger.warn(`markRunning ${msg.jobId} failed: ${e.message}`),
    );
  }

  private async onChunk(ws: WebSocket, msg: ScanJobChunkPayload) {
    const collectorId = this.findCollectorId(ws);
    if (!collectorId) return this.fail(ws, 'protocol_error', 'chunk before hello');
    try {
      await this.observations.ingest(collectorId, msg);
    } catch (e: any) {
      this.logger.error(`observation ingest failed: ${e.message}`);
    }
  }

  private async onDone(ws: WebSocket, msg: ScanJobDonePayload) {
    const collectorId = this.findCollectorId(ws);
    if (!collectorId) return this.fail(ws, 'protocol_error', 'done before hello');
    await this.jobs
      .markCompleted(msg.jobId, msg.sessionId, msg.observationCount)
      .catch((e) => this.logger.warn(`markCompleted ${msg.jobId} failed: ${e.message}`));
    // Fire-and-forget fusion. Errors are logged but don't fail the
    // scan job — fusion is idempotent and runs again on the hourly
    // cron (when we add it). Off the WS thread so a slow fuse
    // doesn't block the gateway.
    this.fusion
      .fuseSession(msg.sessionId)
      .then((summary) =>
        this.logger.log(
          `fusion ${msg.sessionId}: devices=${summary.devices} edges=${summary.edges} events=${summary.events}`,
        ),
      )
      .catch((e) =>
        this.logger.error(`fusion ${msg.sessionId} failed: ${e.message}`),
      );
  }

  private async onError(ws: WebSocket, msg: ScanJobErrorPayload) {
    const collectorId = this.findCollectorId(ws);
    if (!collectorId) return this.fail(ws, 'protocol_error', 'error before hello');
    await this.jobs
      .markFailed(msg.jobId, msg.reason, msg.detail ?? null)
      .catch((e) => this.logger.warn(`markFailed ${msg.jobId} failed: ${e.message}`));
  }

  private fail(ws: WebSocket, code: ErrorPayload['code'], message: string) {
    this.logger.warn(`discovery ws error code=${code} msg=${message}`);
    const err: Frame<ErrorPayload> = { kind: 'error', payload: { code, message } };
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(err));
      ws.close(1008, code);
    }
  }

  private findCollectorId(ws: WebSocket): string | undefined {
    for (const [id, sock] of this.connections) {
      if (sock === ws) return id;
    }
    return undefined;
  }
}

/**
 * Extract the bearer token from the WS handshake. Convention:
 *   Sec-WebSocket-Protocol: itom-collector-token.<token>
 *
 * Two reasons we don't use Authorization:
 *   1. Browser WebSocket clients can't set arbitrary headers; using a
 *      subprotocol header keeps the same path open if we ever ship a
 *      browser-based diagnostic console.
 *   2. The `ws` library auto-echoes the chosen subprotocol back on the
 *      handshake response, so the client knows we accepted the format.
 */
function extractBearerFromHandshake(req: IncomingMessage): string {
  const raw = (req.headers['sec-websocket-protocol'] as string | undefined) ?? '';
  // The header can be a comma-separated list; pick the first token.* one.
  const entries = raw.split(',').map((s) => s.trim());
  for (const entry of entries) {
    if (entry.startsWith('itom-collector-token.')) {
      return entry.slice('itom-collector-token.'.length);
    }
  }
  // Fall back to Authorization for non-browser callers — gorilla can
  // and does set this on Dial.
  const auth = (req.headers['authorization'] as string | undefined) ?? '';
  if (auth.startsWith('Bearer ')) return auth.slice('Bearer '.length);
  return '';
}
