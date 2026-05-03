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
  ) {}

  async register(dto: RegisterAgentDto): Promise<Agent> {
    await this.agentsRepo.upsert(
      {
        agentId: dto.agentId,
        agentVersion: dto.agentVersion,
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
      },
      ['agentId'],
    );
    this.logger.log(`registered agent=${dto.agentId} host=${dto.hostname}`);
    return this.agentsRepo.findOneBy({ agentId: dto.agentId });
  }

  async list(): Promise<Agent[]> {
    return this.agentsRepo.find({
      order: { lastSeenAt: 'DESC' },
    });
  }

  async findOne(agentId: string): Promise<Agent | null> {
    return this.agentsRepo.findOneBy({ agentId });
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
}
