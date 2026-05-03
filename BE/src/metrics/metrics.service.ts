import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Metric } from './metric.entity';
import { NetworkMetric } from './network-metric.entity';
import { DiskMetric } from './disk-metric.entity';
import { CreateMetricsDto } from './dto/create-metrics.dto';
import { Agent } from '../agents/agent.entity';

export type MetricsIngestResult =
  | number
  | { accepted: 0; reason: 'duplicate' };

@Injectable()
export class MetricsService {
  private readonly logger = new Logger(MetricsService.name);

  constructor(
    @InjectRepository(Metric)
    private readonly metricsRepo: Repository<Metric>,
    @InjectRepository(Agent)
    private readonly agentsRepo: Repository<Agent>,
  ) {}

  async ingest(
    dto: CreateMetricsDto,
    requestIdHeader: string | undefined,
  ): Promise<MetricsIngestResult> {
    const requestId = (requestIdHeader ?? dto.requestId)?.trim();
    if (!requestId) {
      this.logger.warn(
        'metrics ingest missing X-Request-Id (and body requestId); accepting without idempotency key',
      );
    }

    return await this.metricsRepo.manager.transaction(async (em) => {
      if (requestId) {
        const inserted: { requestId: string }[] = await em.query(
          `INSERT INTO "request_dedup" ("requestId", "agentId", endpoint)
           VALUES ($1, $2, 'metrics')
           ON CONFLICT ("requestId") DO NOTHING
           RETURNING "requestId"`,
          [requestId, dto.agentId],
        );
        if (!inserted?.length) {
          return { accepted: 0, reason: 'duplicate' as const };
        }
      }

        const metrics = dto.samples.map((s) =>
          em.create(Metric, {
            agentId: dto.agentId,
            timestamp: new Date(s.timestamp),
            cpuPercent: s.cpuPercent,
            memoryPercent: s.memoryPercent,
            diskPercent: s.diskPercent,
            memAvailableBytes:
              s.memAvailableBytes !== undefined && s.memAvailableBytes !== null
                ? s.memAvailableBytes
                : null,
            loadAvg1m:
              s.loadAvg1m !== undefined && s.loadAvg1m !== null
                ? s.loadAvg1m
                : null,
            processCount:
              s.processCount !== undefined && s.processCount !== null
                ? s.processCount
                : null,
          }),
        );
        await em.save(metrics);

        const networkRows: NetworkMetric[] = [];
        const diskRows: DiskMetric[] = [];

        for (const s of dto.samples) {
          const ts = new Date(s.timestamp);
          if (s.network?.length) {
            for (const n of s.network) {
              networkRows.push(
                em.create(NetworkMetric, {
                  agentId: dto.agentId,
                  interfaceName: n.interfaceName,
                  timestamp: ts,
                  bytesSent: n.bytesSent,
                  bytesRecv: n.bytesRecv,
                  packetsSent: n.packetsSent,
                  packetsRecv: n.packetsRecv,
                }),
              );
            }
          }
          if (s.disks?.length) {
            for (const d of s.disks) {
              diskRows.push(
                em.create(DiskMetric, {
                  agentId: dto.agentId,
                  mountpoint: d.mountpoint,
                  timestamp: ts,
                  usedPercent: d.usedPercent,
                  usedBytes: d.usedBytes,
                  totalBytes: d.totalBytes,
                }),
              );
            }
          }
        }

        if (networkRows.length) {
          await em.save(networkRows);
        }
        if (diskRows.length) {
          await em.save(diskRows);
        }

        const maxTs = dto.samples.reduce((acc, s) => {
          const t = new Date(s.timestamp).getTime();
          return t > acc ? t : acc;
        }, 0);
        const maxDate = new Date(maxTs);
        const now = new Date();

        const agent = await em.findOne(Agent, {
          where: { agentId: dto.agentId },
        });
        const patch: Partial<Agent> = { lastSeenAt: maxDate };
        if (agent && agent.status !== 'online') {
          patch.status = 'online';
          patch.statusChangedAt = now;
        }
        await em.update(Agent, { agentId: dto.agentId }, patch);

        this.logger.log(
          `accepted ${dto.samples.length} sample(s) from agent=${dto.agentId}`,
        );
        return dto.samples.length;
    });
  }

  async list(agentId: string | undefined, limit: number) {
    const qb = this.metricsRepo
      .createQueryBuilder('m')
      .orderBy('m.timestamp', 'DESC')
      .limit(limit);
    if (agentId) qb.where('m.agentId = :agentId', { agentId });
    return qb.getMany();
  }

  async listAgents() {
    const rows = await this.metricsRepo
      .createQueryBuilder('m')
      .select('m.agentId', 'agentId')
      .addSelect('MAX(m.timestamp)', 'lastSeen')
      .addSelect('COUNT(*)', 'sampleCount')
      .groupBy('m.agentId')
      .getRawMany();

    return rows.map((r) => ({
      agentId: r.agentId,
      lastSeen: new Date(r.lastSeen),
      sampleCount: parseInt(r.sampleCount, 10),
    }));
  }
}
