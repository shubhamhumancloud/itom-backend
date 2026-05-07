import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Agent } from './agent.entity';
import { RegisterAgentDto } from './dto/register-agent.dto';
import { HeartbeatDto } from './dto/heartbeat.dto';
import { AgentHeartbeat } from './agent-heartbeat.entity';

export type HeartbeatResult =
  | { accepted: true }
  | { accepted: false; reason: 'duplicate' };

@Injectable()
export class AgentsService {
  private readonly logger = new Logger(AgentsService.name);

  constructor(
    @InjectRepository(Agent)
    private readonly agentsRepo: Repository<Agent>,
    @InjectRepository(AgentHeartbeat)
    private readonly heartbeatsRepo: Repository<AgentHeartbeat>,
  ) {}

  async register(
    dto: RegisterAgentDto,
  ): Promise<Agent & { reassigned?: boolean }> {
    // 1. Fast path: agentId is already known — update in place.
    let existing = await this.agentsRepo.findOneBy({ agentId: dto.agentId });
    let canonicalAgentId = dto.agentId;
    let reassigned = false;

    // 2. Fallback path: agentId is new but fingerprint matches an existing
    //    record under the same tenant. This happens when the host's
    //    fingerprint inputs drift (e.g. NIC swap) and the agent computes a
    //    new deterministic ID. We redirect the agent to the existing record
    //    instead of creating a duplicate.
    if (!existing && dto.fingerprintHash) {
      const tenantScope = dto.tenantId ?? null;
      const match = await this.agentsRepo.findOne({
        where: {
          fingerprintHash: dto.fingerprintHash,
          ...(tenantScope ? { tenantId: tenantScope } : {}),
        },
      });
      if (match) {
        canonicalAgentId = match.agentId;
        existing = match;
        reassigned = true;
        this.logger.warn(
          `fingerprint reconciliation: agent claimed=${dto.agentId} ` +
            `→ canonical=${match.agentId} (host=${dto.hostname})`,
        );
      }
    }

    await this.agentsRepo.upsert(
      {
        agentId: canonicalAgentId,
        agentVersion: dto.agentVersion,
        fingerprintHash: dto.fingerprintHash ?? existing?.fingerprintHash,
        hostname: dto.hostname,
        os: dto.os,
        arch: dto.arch,
        platform: dto.platform,
        platformVersion: dto.platformVersion,
        kernelVersion: dto.kernelVersion,
        ethernetIPs: dto.ethernetIPs,
        wifiIPs: dto.wifiIPs,
        macAddresses: dto.macAddresses,
        cpuModel: dto.cpuModel,
        cpuCores: dto.cpuCores,
        totalMemoryBytes: dto.totalMemoryBytes,
        totalDiskBytes: dto.totalDiskBytes,
        // Only set tenantId if provided AND not already bound — never overwrite.
        tenantId: dto.tenantId ?? existing?.tenantId ?? null,
      },
      ['agentId'],
    );

    this.logger.log(
      `registered agent=${canonicalAgentId} host=${dto.hostname} tenant=${
        dto.tenantId ?? existing?.tenantId ?? '-'
      }${reassigned ? ' (reassigned)' : ''}`,
    );

    const saved = await this.agentsRepo.findOneBy({ agentId: canonicalAgentId });
    return { ...saved, reassigned } as Agent & { reassigned?: boolean };
  }

  async claimOrphans(tenantId: string): Promise<{ updatedAgents: number }> {
    const result = await this.agentsRepo
      .createQueryBuilder()
      .update(Agent)
      .set({ tenantId })
      .where('"tenantId" IS NULL')
      .execute();
    this.logger.log(
      `claim-orphans tenant=${tenantId} updated=${result.affected ?? 0}`,
    );
    return { updatedAgents: result.affected ?? 0 };
  }

  async list(tenantId?: string | null): Promise<Agent[]> {
    const where = tenantId ? { tenantId } : {};
    return this.agentsRepo.find({
      where,
      order: { lastSeenAt: 'DESC' },
    });
  }

  async findOne(agentId: string, tenantId?: string | null): Promise<Agent | null> {
    const where = tenantId ? { agentId, tenantId } : { agentId };
    return this.agentsRepo.findOneBy(where);
  }

  async findByFingerprint(fingerprintHash: string): Promise<Agent | null> {
    if (!fingerprintHash) return null;
    return this.agentsRepo.findOneBy({ fingerprintHash });
  }

  /**
   * Called by the WebSocket gateway on `hello`. Replaces the old REST
   * heartbeat for liveness — the connection itself is the heartbeat.
   */
  async markOnline(agentId: string, agentVersion?: string): Promise<void> {
    const now = new Date();
    const patch: Partial<Agent> = {
      status: 'online',
      statusChangedAt: now,
      lastSeenAt: now,
    };
    if (agentVersion) patch.agentVersion = agentVersion;
    await this.agentsRepo.update({ agentId }, patch);
  }

  /** Called by the WebSocket gateway on disconnect. */
  async markOffline(agentId: string): Promise<void> {
    await this.agentsRepo.update(
      { agentId },
      { status: 'offline', statusChangedAt: new Date() },
    );
  }

  async recordHeartbeat(
    dto: HeartbeatDto,
    requestIdHeader: string | undefined,
  ): Promise<HeartbeatResult> {
    const requestId = requestIdHeader?.trim();
    if (!requestId) {
      this.logger.warn(
        'heartbeat missing X-Request-Id; accepting without idempotency key',
      );
    }

    return this.agentsRepo.manager.transaction(async (em) => {
      if (requestId) {
        const inserted: { requestId: string }[] = await em.query(
          `INSERT INTO "request_dedup" ("requestId", "agentId", endpoint)
           VALUES ($1, $2, 'heartbeat')
           ON CONFLICT ("requestId") DO NOTHING
           RETURNING "requestId"`,
          [requestId, dto.agentId],
        );
        if (!inserted?.length) {
          return { accepted: false, reason: 'duplicate' as const };
        }
      }

      const ts = new Date(dto.timestamp);
      const uptime =
        dto.uptimeSeconds !== undefined && dto.uptimeSeconds !== null
          ? dto.uptimeSeconds
          : null;

      await em.save(
        em.create(AgentHeartbeat, {
          agentId: dto.agentId,
          timestamp: ts,
          agentVersion: dto.agentVersion ?? null,
          uptimeSeconds: uptime,
        }),
      );

      const agent = await em.findOne(Agent, { where: { agentId: dto.agentId } });
      const now = new Date();
      const patch: Partial<Agent> = { lastSeenAt: ts };
      if (agent && agent.status !== 'online') {
        patch.status = 'online';
        patch.statusChangedAt = now;
      }
      await em.update(Agent, { agentId: dto.agentId }, patch);

      return { accepted: true };
    });
  }

  async listHeartbeats(
    agentId: string,
    limit = 100,
    tenantId?: string | null,
  ): Promise<AgentHeartbeat[]> {
    if (tenantId) {
      const owns = await this.agentsRepo.findOneBy({ agentId, tenantId });
      if (!owns) return [];
    }
    return this.heartbeatsRepo.find({
      where: { agentId },
      order: { timestamp: 'DESC' },
      take: limit,
    });
  }
}
