import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, LessThan, Repository } from 'typeorm';
import { ProcessMetric } from './entities/process-metric.entity';
import { BatteryMetric } from './entities/battery-metric.entity';
import { SensorMetric } from './entities/sensor-metric.entity';
import { DiskHealth } from './entities/disk-health.entity';
import { GpuMetric } from './entities/gpu-metric.entity';
import { SoftwareItem } from './entities/software-item.entity';
import {
  BatteryMsg,
  DiskHealthMsg,
  GpuMsg,
  ProcessesMsg,
  SensorsMsg,
  SoftwareInventoryMsg,
} from '../agents/ws/protocol';

@Injectable()
export class ObservabilityService {
  private readonly logger = new Logger(ObservabilityService.name);

  constructor(
    @InjectRepository(ProcessMetric)
    private readonly processRepo: Repository<ProcessMetric>,
    @InjectRepository(BatteryMetric)
    private readonly batteryRepo: Repository<BatteryMetric>,
    @InjectRepository(SensorMetric)
    private readonly sensorRepo: Repository<SensorMetric>,
    @InjectRepository(DiskHealth)
    private readonly diskRepo: Repository<DiskHealth>,
    @InjectRepository(GpuMetric)
    private readonly gpuRepo: Repository<GpuMetric>,
    @InjectRepository(SoftwareItem)
    private readonly softwareRepo: Repository<SoftwareItem>,
  ) {}

  // ---------- Ingest (called from WS gateway) ----------

  async ingestProcesses(agentId: string, msg: ProcessesMsg): Promise<void> {
    if (!msg.processes?.length) return;
    const ts = new Date(msg.timestamp);
    const rows = msg.processes.map((p) =>
      this.processRepo.create({
        agentId,
        timestamp: ts,
        processName: p.name,
        pidCount: p.pidCount ?? 1,
        cpuPercent: p.cpuPercent ?? 0,
        memoryBytes: p.memoryBytes ?? 0,
        ioReadBytes: p.ioReadBytes ?? null,
        ioWriteBytes: p.ioWriteBytes ?? null,
      }),
    );
    await this.processRepo.insert(rows);
  }

  async ingestBattery(agentId: string, msg: BatteryMsg): Promise<void> {
    await this.batteryRepo.insert({
      agentId,
      timestamp: new Date(msg.timestamp),
      percent: msg.percent,
      charging: msg.charging,
      onAC: msg.onAC,
      cycleCount: msg.cycleCount ?? null,
      designCapacityMwh: msg.designCapacityMwh ?? null,
      fullCapacityMwh: msg.fullCapacityMwh ?? null,
      healthPercent: msg.healthPercent ?? null,
      timeToFullSeconds: msg.timeToFullSeconds ?? null,
      timeToEmptySeconds: msg.timeToEmptySeconds ?? null,
    });
  }

  async ingestSensors(agentId: string, msg: SensorsMsg): Promise<void> {
    if (!msg.readings?.length) return;
    const ts = new Date(msg.timestamp);
    const rows = msg.readings.map((r) =>
      this.sensorRepo.create({
        agentId,
        timestamp: ts,
        name: r.name,
        kind: r.kind,
        value: r.value,
      }),
    );
    await this.sensorRepo.insert(rows);
  }

  async ingestDiskHealth(agentId: string, msg: DiskHealthMsg): Promise<void> {
    if (!msg.drives?.length) return;
    const ts = new Date(msg.timestamp);
    const rows = msg.drives.map((d) =>
      this.diskRepo.create({
        agentId,
        timestamp: ts,
        device: d.device,
        model: d.model ?? null,
        status: d.status,
        predictedFailure: d.predictedFailure ?? false,
        temperatureC: d.temperatureC ?? null,
        powerOnHours: d.powerOnHours ?? null,
        reallocatedSectors: d.reallocatedSectors ?? null,
        wearLevelingPercent: d.wearLevelingPercent ?? null,
      }),
    );
    await this.diskRepo.insert(rows);
  }

  async ingestGpu(agentId: string, msg: GpuMsg): Promise<void> {
    if (!msg.gpus?.length) return;
    const ts = new Date(msg.timestamp);
    const rows = msg.gpus.map((g) =>
      this.gpuRepo.create({
        agentId,
        timestamp: ts,
        gpuIndex: g.index,
        name: g.name,
        utilizationPercent: g.utilizationPercent,
        memoryUsedBytes: g.memoryUsedBytes,
        memoryTotalBytes: g.memoryTotalBytes,
        temperatureC: g.temperatureC ?? null,
        powerWatts: g.powerWatts ?? null,
      }),
    );
    await this.gpuRepo.insert(rows);
  }

  async ingestSoftware(
    agentId: string,
    msg: SoftwareInventoryMsg,
  ): Promise<void> {
    if (!msg.items?.length) return;
    const now = new Date();
    // Upsert each item; firstSeenAt is preserved by ON CONFLICT DO UPDATE skip.
    for (const item of msg.items) {
      await this.softwareRepo
        .createQueryBuilder()
        .insert()
        .values({
          agentId,
          name: item.name,
          version: item.version,
          publisher: item.publisher ?? null,
          installedAt: item.installedAt ?? null,
          sizeBytes: item.sizeBytes ?? null,
          source: item.source,
          firstSeenAt: now,
          lastSeenAt: now,
        })
        .orUpdate(
          ['publisher', 'installedAt', 'sizeBytes', 'source', 'lastSeenAt'],
          ['agentId', 'name', 'version'],
        )
        .execute();
    }
  }

  // ---------- Reads (controller) ----------

  /**
   * Top processes for an agent at the most recent sample. We pick the latest
   * timestamp first, then pull rows for it. Sorted client-side.
   */
  async latestProcesses(agentId: string, limit = 100): Promise<ProcessMetric[]> {
    const latest = await this.processRepo
      .createQueryBuilder('p')
      .select('p.timestamp', 'ts')
      .where('p.agentId = :agentId', { agentId })
      .orderBy('p.timestamp', 'DESC')
      .limit(1)
      .getRawOne<{ ts: Date }>();
    if (!latest?.ts) return [];
    return this.processRepo.find({
      where: { agentId, timestamp: latest.ts },
      take: limit,
    });
  }

  /** Time series for one process name over the last N samples — for sparklines. */
  async processSeries(
    agentId: string,
    processName: string,
    limit = 60,
  ): Promise<ProcessMetric[]> {
    return this.processRepo.find({
      where: { agentId, processName },
      order: { timestamp: 'DESC' },
      take: limit,
    });
  }

  /** Bulk sparkline fetch — one query, multiple processNames, last N points each. */
  async processSeriesBulk(
    agentId: string,
    names: string[],
    limit = 30,
  ): Promise<Record<string, { t: string; cpu: number; mem: number }[]>> {
    if (!names.length) return {};
    const rows = await this.processRepo.find({
      where: { agentId, processName: In(names) },
      order: { timestamp: 'DESC' },
      take: names.length * limit,
    });
    const byName: Record<string, { t: string; cpu: number; mem: number }[]> = {};
    for (const r of rows) {
      const arr = byName[r.processName] ?? (byName[r.processName] = []);
      if (arr.length < limit) {
        arr.push({
          t: r.timestamp.toISOString(),
          cpu: Number(r.cpuPercent),
          mem: Number(r.memoryBytes),
        });
      }
    }
    // Reverse to oldest-first for charting.
    for (const k of Object.keys(byName)) byName[k].reverse();
    return byName;
  }

  async batteryHistory(agentId: string, limit = 100): Promise<BatteryMetric[]> {
    return this.batteryRepo.find({
      where: { agentId },
      order: { timestamp: 'DESC' },
      take: limit,
    });
  }

  async sensorHistory(
    agentId: string,
    kind?: 'temperature_c' | 'fan_rpm',
    limit = 200,
  ): Promise<SensorMetric[]> {
    const where = kind ? { agentId, kind } : { agentId };
    return this.sensorRepo.find({
      where,
      order: { timestamp: 'DESC' },
      take: limit,
    });
  }

  /** Latest reading per device — what the UI shows as a card. */
  async latestDiskHealth(agentId: string): Promise<DiskHealth[]> {
    const rows = await this.diskRepo
      .createQueryBuilder('d')
      .distinctOn(['d.device'])
      .where('d.agentId = :agentId', { agentId })
      .orderBy('d.device', 'ASC')
      .addOrderBy('d.timestamp', 'DESC')
      .getMany();
    return rows;
  }

  async latestGpu(agentId: string): Promise<GpuMetric[]> {
    const rows = await this.gpuRepo
      .createQueryBuilder('g')
      .distinctOn(['g.gpuIndex'])
      .where('g.agentId = :agentId', { agentId })
      .orderBy('g.gpuIndex', 'ASC')
      .addOrderBy('g.timestamp', 'DESC')
      .getMany();
    return rows;
  }

  async gpuHistory(agentId: string, limit = 120): Promise<GpuMetric[]> {
    return this.gpuRepo.find({
      where: { agentId },
      order: { timestamp: 'DESC' },
      take: limit,
    });
  }

  /**
   * Software inventory list — searchable + cursor-paginated for infinite scroll.
   * Cursor = name of the last row seen (alphabetical). Limit capped to 200.
   */
  async listSoftware(
    agentId: string,
    opts: { search?: string; cursor?: string; limit?: number } = {},
  ): Promise<{ items: SoftwareItem[]; nextCursor: string | null }> {
    const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
    const qb = this.softwareRepo
      .createQueryBuilder('s')
      .where('s.agentId = :agentId', { agentId });

    if (opts.search) {
      qb.andWhere(
        '(s.name ILIKE :q OR s.publisher ILIKE :q OR s.version ILIKE :q)',
        { q: `%${opts.search}%` },
      );
    }
    if (opts.cursor) {
      qb.andWhere('(s.name, s.version) > (:cursorName, :cursorVersion)', {
        cursorName: opts.cursor,
        cursorVersion: '',
      });
    }

    qb.orderBy('s.name', 'ASC').addOrderBy('s.version', 'ASC').take(limit + 1);

    const rows = await qb.getMany();
    const hasMore = rows.length > limit;
    const items = hasMore ? rows.slice(0, limit) : rows;
    const nextCursor = hasMore ? items[items.length - 1].name : null;
    return { items, nextCursor };
  }
}
