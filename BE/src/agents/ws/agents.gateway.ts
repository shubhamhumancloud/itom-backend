import { Inject, Logger, OnModuleInit, forwardRef } from '@nestjs/common';
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { IncomingMessage } from 'http';
import { WebSocket, WebSocketServer as WSServer } from 'ws';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { AgentsService } from '../agents.service';
import { MetricsService } from '../../metrics/metrics.service';
import { CreateMetricsDto } from '../../metrics/dto/create-metrics.dto';
import { ObservabilityService } from '../../observability/observability.service';
import {
  AckMsg,
  ClientMsg,
  ErrorMsg,
  MAX_FRAME_BYTES,
  ServerMsg,
  WelcomeMsg,
} from './protocol';

/**
 * Connection lifecycle
 * --------------------
 *  - Agent dials wss://server/v1/ws.
 *  - Backend assigns a temporary connId and waits for a `hello` frame.
 *  - On hello: validate, mark agent online in DB, send `welcome`.
 *  - From then on: route `metrics` to MetricsService, reply with `ack`.
 *  - On any disconnect: mark agent offline, drop from `connections`.
 *
 * Liveness
 * --------
 *  Server sends a ping every 30 s. If no pong arrives within ~30 s of the
 *  next tick, `ws` library closes the socket and `handleDisconnect` runs.
 *  This replaces the old REST /v1/agents/heartbeat polling.
 *
 * Server-push
 * -----------
 *  `connections` keeps `agentId → WebSocket`. Anything that wants to push to
 *  a specific agent (config update, ad-hoc command) calls `sendTo(agentId)`.
 *  Currently unused but laid out for the next iteration.
 */
@WebSocketGateway({
  path: '/v1/ws',
  maxPayload: MAX_FRAME_BYTES,
})
export class AgentsGateway
  implements OnGatewayConnection, OnGatewayDisconnect, OnModuleInit
{
  private readonly logger = new Logger(AgentsGateway.name);
  private readonly heartbeatIntervalMs = 30_000;
  private heartbeatTimer?: NodeJS.Timeout;

  /** agentId → live socket. Populated only after a successful `hello`. */
  private readonly connections = new Map<string, WebSocket>();

  /** Sockets that connected but have not yet sent `hello`. */
  private readonly pending = new WeakMap<
    WebSocket,
    { connectedAt: number; remoteAddr: string }
  >();

  /** ws instances that have responded to the most recent ping. */
  private readonly alive = new WeakSet<WebSocket>();

  @WebSocketServer()
  private readonly server: WSServer;

  constructor(
    private readonly agentsService: AgentsService,
    private readonly metricsService: MetricsService,
    @Inject(forwardRef(() => ObservabilityService))
    private readonly obs: ObservabilityService,
  ) {}

  onModuleInit() {
    // Server-side ping/pong loop. Detects half-open TCP connections (laptop
    // sleep, NAT timeout, network partition) within one heartbeat interval.
    this.heartbeatTimer = setInterval(() => {
      for (const ws of this.server?.clients ?? []) {
        if (!this.alive.has(ws)) {
          this.logger.warn('terminating unresponsive socket');
          ws.terminate();
          continue;
        }
        this.alive.delete(ws);
        try {
          ws.ping();
        } catch (e) {
          this.logger.warn(`ping failed: ${e}`);
        }
      }
    }, this.heartbeatIntervalMs);
  }

  handleConnection(ws: WebSocket, req: IncomingMessage) {
    const remoteAddr =
      (req.headers['x-forwarded-for'] as string) ?? req.socket.remoteAddress ?? 'unknown';
    this.pending.set(ws, { connectedAt: Date.now(), remoteAddr });
    this.alive.add(ws);
    ws.on('pong', () => this.alive.add(ws));
    ws.on('message', (data) => this.onMessage(ws, data.toString()));
    ws.on('error', (err) => this.logger.warn(`socket error: ${err.message}`));
    this.logger.log(`socket connected from ${remoteAddr}`);
  }

  handleDisconnect(ws: WebSocket) {
    const agentId = this.findAgentId(ws);
    if (agentId) {
      this.connections.delete(agentId);
      // Mark offline immediately — we know the connection dropped.
      this.agentsService
        .markOffline(agentId)
        .catch((e) =>
          this.logger.warn(`markOffline ${agentId} failed: ${e.message}`),
        );
      this.logger.log(`agent disconnected agentId=${agentId}`);
    } else {
      this.logger.log('pending socket disconnected before hello');
    }
  }

  // -----------------------------------------------------------------
  // Server-push API (used by other services to send to a specific agent)
  // -----------------------------------------------------------------

  /** Push a message to a connected agent. Returns false if not connected. */
  sendTo(agentId: string, msg: ServerMsg): boolean {
    const ws = this.connections.get(agentId);
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    ws.send(JSON.stringify(msg));
    return true;
  }

  // -----------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------

  private async onMessage(ws: WebSocket, raw: string) {
    let parsed: ClientMsg;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return this.fail(ws, 'protocol_error', 'malformed JSON');
    }
    if (!parsed || typeof parsed !== 'object' || !('type' in parsed)) {
      return this.fail(ws, 'protocol_error', 'missing type');
    }

    switch (parsed.type) {
      case 'hello':
        return this.onHello(ws, parsed);
      case 'metrics':
        return this.onMetrics(ws, parsed);
      case 'processes':
      case 'battery':
      case 'sensors':
      case 'gpu':
      case 'software_inventory':
        return this.onObservability(ws, parsed);
      case 'bye':
        ws.close(1000, 'client requested goodbye');
        return;
      default:
        return this.fail(ws, 'protocol_error', `unknown type: ${(parsed as any).type}`);
    }
  }

  private async onObservability(ws: WebSocket, msg: ClientMsg) {
    const agentId = this.findAgentId(ws);
    if (!agentId) return this.fail(ws, 'protocol_error', `${msg.type} before hello`);
    const reqId = (msg as any).requestId ?? '';
    try {
      switch (msg.type) {
        case 'processes':
          await this.obs.ingestProcesses(agentId, msg);
          break;
        case 'battery':
          await this.obs.ingestBattery(agentId, msg);
          break;
        case 'sensors':
          await this.obs.ingestSensors(agentId, msg);
          break;
        case 'gpu':
          await this.obs.ingestGpu(agentId, msg);
          break;
        case 'software_inventory':
          await this.obs.ingestSoftware(agentId, msg);
          break;
      }
      return this.ack(ws, reqId, 'committed');
    } catch (e: any) {
      this.logger.error(`${msg.type} ingest failed: ${e.message}`);
      return this.ack(ws, reqId, 'rejected', 'internal error');
    }
  }

  private async onHello(ws: WebSocket, msg: ClientMsg & { type: 'hello' }) {
    if (this.findAgentId(ws)) {
      return this.fail(ws, 'protocol_error', 'hello already received');
    }
    if (!msg.agentId || typeof msg.agentId !== 'string') {
      return this.fail(ws, 'protocol_error', 'hello missing agentId');
    }

    // Reuse the same fingerprint reconciliation logic as REST register, but
    // we don't have the full device payload here. Look up by id only.
    let agent = await this.agentsService.findOne(msg.agentId);
    let canonicalAgentId = msg.agentId;
    let reassigned = false;

    if (!agent && msg.fingerprintHash) {
      const match = await this.agentsService.findByFingerprint(msg.fingerprintHash);
      if (match) {
        agent = match;
        canonicalAgentId = match.agentId;
        reassigned = true;
      }
    }

    if (!agent) {
      // Agent should have called REST /v1/agents/register before connecting.
      // Reject so the agent retries registration on its next reconnect.
      return this.fail(
        ws,
        'unknown_agent',
        'agent not registered; call POST /v1/agents/register first',
      );
    }

    // Promote socket from `pending` to `connections`.
    this.pending.delete(ws);
    // If the agent had a stale socket (e.g. previous instance), close it.
    const prev = this.connections.get(canonicalAgentId);
    if (prev && prev !== ws) {
      this.logger.warn(`replacing stale socket for ${canonicalAgentId}`);
      try {
        prev.close(1000, 'replaced by newer connection');
      } catch {
        /* noop */
      }
    }
    this.connections.set(canonicalAgentId, ws);

    await this.agentsService.markOnline(canonicalAgentId, msg.agentVersion);

    const welcome: WelcomeMsg = {
      type: 'welcome',
      agentId: canonicalAgentId,
      reassigned,
      heartbeatIntervalSeconds: this.heartbeatIntervalMs / 1000,
    };
    ws.send(JSON.stringify(welcome));
    this.logger.log(
      `agent online agentId=${canonicalAgentId} version=${msg.agentVersion}` +
        (reassigned ? ' (reassigned)' : ''),
    );
  }

  private async onMetrics(ws: WebSocket, msg: ClientMsg & { type: 'metrics' }) {
    const agentId = this.findAgentId(ws);
    if (!agentId) {
      return this.fail(ws, 'protocol_error', 'metrics before hello');
    }
    if (!msg.requestId || !Array.isArray(msg.samples) || msg.samples.length === 0) {
      return this.ack(ws, msg.requestId ?? '', 'rejected', 'invalid metrics frame');
    }

    // Validate via the same DTO REST uses, so behaviour is identical.
    const dto = plainToInstance(CreateMetricsDto, {
      agentId,
      requestId: msg.requestId,
      samples: msg.samples,
    });
    const errors = await validate(dto, { whitelist: true });
    if (errors.length > 0) {
      this.logger.warn(`metrics validation failed: ${errors.length} issue(s)`);
      return this.ack(ws, msg.requestId, 'rejected', 'validation failed');
    }

    try {
      const result = await this.metricsService.ingest(dto, msg.requestId);
      if (typeof result === 'object' && result?.reason === 'duplicate') {
        return this.ack(ws, msg.requestId, 'duplicate');
      }
      return this.ack(ws, msg.requestId, 'committed');
    } catch (e: any) {
      this.logger.error(`metrics ingest failed: ${e.message}`);
      return this.ack(ws, msg.requestId, 'rejected', 'internal error');
    }
  }

  private ack(
    ws: WebSocket,
    requestId: string,
    result: AckMsg['result'],
    message?: string,
  ) {
    const ack: AckMsg = { type: 'ack', requestId, result, ...(message ? { message } : {}) };
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(ack));
  }

  private fail(ws: WebSocket, code: ErrorMsg['code'], message: string) {
    this.logger.warn(`ws error code=${code} msg=${message}`);
    const err: ErrorMsg = { type: 'error', code, message };
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(err));
      // For auth/protocol failures, close. The agent should reconnect.
      ws.close(1008, code);
    }
  }

  private findAgentId(ws: WebSocket): string | undefined {
    for (const [id, sock] of this.connections) {
      if (sock === ws) return id;
    }
    return undefined;
  }
}
