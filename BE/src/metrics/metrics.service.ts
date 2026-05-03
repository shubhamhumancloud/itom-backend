import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Metric } from './metric.entity';
import { NetworkMetric } from './network-metric.entity';
import { DiskMetric } from './disk-metric.entity';
import { CreateMetricsDto } from './dto/create-metrics.dto';
import { AgentsService } from '../agents/agents.service';

@Injectable()
export class MetricsService {
  private readonly logger = new Logger(MetricsService.name);

  constructor(
    @InjectRepository(Metric)
    private readonly metricsRepo: Repository<Metric>,
    private readonly agentsService: AgentsService,
  ) {}

  async ingest(dto: CreateMetricsDto): Promise<number> {
    await this.metricsRepo.manager.transaction(async (em) => {
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
    });

    this.agentsService.touchLastSeen(dto.agentId).catch(() => null);
    this.logger.log(
      `accepted ${dto.samples.length} sample(s) from agent=${dto.agentId}`,
    );
    return dto.samples.length;
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
