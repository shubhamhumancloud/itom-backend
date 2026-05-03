import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Agent } from './agent.entity';
import { RequestDedup } from './request-dedup.entity';

@Injectable()
export class AgentsSchedulerService {
  private readonly logger = new Logger(AgentsSchedulerService.name);

  constructor(
    @InjectRepository(Agent)
    private readonly agentsRepo: Repository<Agent>,
    @InjectRepository(RequestDedup)
    private readonly dedupRepo: Repository<RequestDedup>,
  ) {}

  @Cron('*/30 * * * * *')
  async markStaleAgentsOffline(): Promise<void> {
    const cutoff = new Date(Date.now() - 90_000);
    const stale = await this.agentsRepo
      .createQueryBuilder('a')
      .where('a.status = :st', { st: 'online' })
      .andWhere('a.lastSeenAt IS NOT NULL')
      .andWhere('a.lastSeenAt < :cutoff', { cutoff })
      .getMany();

    for (const a of stale) {
      await this.agentsRepo.update(
        { agentId: a.agentId },
        { status: 'offline', statusChangedAt: new Date() },
      );
      this.logger.warn(
        `agent ${a.agentId} went offline (lastSeen: ${a.lastSeenAt?.toISOString()})`,
      );
    }
  }

  @Cron('0 */15 * * * *')
  async pruneRequestDedup(): Promise<void> {
    const cutoff = new Date(Date.now() - 60 * 60 * 1000);
    const res = await this.dedupRepo
      .createQueryBuilder()
      .delete()
      .from(RequestDedup)
      .where('createdAt < :cutoff', { cutoff })
      .execute();
    this.logger.debug(`pruned ${res.affected ?? 0} request_dedup row(s)`);
  }
}
