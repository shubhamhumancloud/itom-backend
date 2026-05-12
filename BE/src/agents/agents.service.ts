import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Agent } from './agent.entity';
import { RegisterAgentDto } from './dto/register-agent.dto';
import { AgentStatusEvent } from './agent-status-event.entity';

@Injectable()
export class AgentsService {
  private readonly logger = new Logger(AgentsService.name);

  constructor(
    @InjectRepository(Agent)
    private readonly agentsRepo: Repository<Agent>,
    @InjectRepository(AgentStatusEvent)
    private readonly statusEventsRepo: Repository<AgentStatusEvent>,
  ) {}

  async register(
    dto: RegisterAgentDto,
  ): Promise<Agent & { reassigned?: boolean }> {
    // 1. Fast path: agentId is already known — update in place.
    let existing = await this.agentsRepo.findOneBy({ agentId: dto.agentId });
    let canonicalAgentId = dto.agentId;
    let reassigned = false;

    // 2. Fallback path: agentId is new but fingerprint matches an existing
    //    record under the same tenant. We try the new (hardware-UUID-based)
    //    hash first, then the legacy (MAC-based) hash so devices that
    //    upgraded in place still resolve to their original AgentID instead
    //    of creating a duplicate row.
    //
    //    The legacy lookup can be removed two releases after the new
    //    formula ships (every active agent will have re-registered with
    //    the new hash by then).
    if (!existing && (dto.fingerprintHash || dto.legacyFingerprintHash)) {
      const tenantScope = dto.tenantId ?? null;
      const baseWhere = tenantScope ? { tenantId: tenantScope } : {};

      let match: Agent | null = null;
      let matchedVia: 'new' | 'legacy' | null = null;

      if (dto.fingerprintHash) {
        match = await this.agentsRepo.findOne({
          where: { ...baseWhere, fingerprintHash: dto.fingerprintHash },
        });
        if (match) matchedVia = 'new';
      }
      if (!match && dto.legacyFingerprintHash) {
        match = await this.agentsRepo.findOne({
          where: { ...baseWhere, fingerprintHash: dto.legacyFingerprintHash },
        });
        if (match) matchedVia = 'legacy';
      }

      if (match) {
        canonicalAgentId = match.agentId;
        existing = match;
        reassigned = true;
        this.logger.warn(
          `fingerprint reconciliation (via=${matchedVia}): ` +
            `agent claimed=${dto.agentId} → canonical=${match.agentId} ` +
            `(host=${dto.hostname})`,
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
   * Called by the WebSocket gateway on `hello`. The WS connection itself is
   * the liveness signal, so this updates `agents.status` and only writes an
   * `agent_status_events` row when the status actually changed online→offline
   * or offline→online. No per-tick rows.
   */
  async markOnline(agentId: string, agentVersion?: string): Promise<void> {
    await this.agentsRepo.manager.transaction(async (em) => {
      const agent = await em.findOne(Agent, { where: { agentId } });
      if (!agent) return;

      const now = new Date();
      const becameOnline = agent.status !== 'online';

      const patch: Partial<Agent> = { lastSeenAt: now };
      if (becameOnline) {
        patch.status = 'online';
        patch.statusChangedAt = now;
      }
      if (agentVersion) patch.agentVersion = agentVersion;

      await em.update(Agent, { agentId }, patch);

      if (becameOnline) {
        await em.save(
          em.create(AgentStatusEvent, {
            agentId,
            tenantId: agent.tenantId ?? null,
            status: 'online',
            occurredAt: now,
            agentVersion: agentVersion ?? agent.agentVersion ?? null,
          }),
        );
      }
    });
  }

  /** Called by the WebSocket gateway on disconnect. */
  async markOffline(agentId: string): Promise<void> {
    await this.agentsRepo.manager.transaction(async (em) => {
      const agent = await em.findOne(Agent, { where: { agentId } });
      if (!agent) return;

      if (agent.status === 'offline') return; // already offline, no transition

      const now = new Date();
      await em.update(
        Agent,
        { agentId },
        { status: 'offline', statusChangedAt: now },
      );

      await em.save(
        em.create(AgentStatusEvent, {
          agentId,
          tenantId: agent.tenantId ?? null,
          status: 'offline',
          occurredAt: now,
          agentVersion: agent.agentVersion ?? null,
        }),
      );
    });
  }

  async listStatusEvents(
    agentId: string,
    limit = 100,
    tenantId?: string | null,
  ): Promise<AgentStatusEvent[]> {
    if (tenantId) {
      const owns = await this.agentsRepo.findOneBy({ agentId, tenantId });
      if (!owns) return [];
    }
    return this.statusEventsRepo.find({
      where: { agentId },
      order: { occurredAt: 'DESC' },
      take: limit,
    });
  }
}
