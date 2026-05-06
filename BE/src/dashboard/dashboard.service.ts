import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Agent } from '../agents/agent.entity';
import { AgentHeartbeat } from '../agents/agent-heartbeat.entity';
import { Metric } from '../metrics/metric.entity';

export interface DashboardSummary {
  totalAgents: number;
  onlineAgents: number;
  offlineAgents: number;
  unknownAgents: number;
  avgCpu: number;
  avgMemory: number;
  avgDisk: number;
  totalMemoryBytes: number;
  totalDiskBytes: number;
  lastUpdatedAt: string;
}

export interface ActivityTrendPoint {
  date: string;
  heartbeats: number;
  agents: number;
}

export interface OsDistributionEntry {
  os: string;
  count: number;
}

export interface CpuByAgentEntry {
  agentId: string;
  hostname: string;
  os: string | null;
  cpuPercent: number;
  memoryPercent: number;
  diskPercent: number;
  status: string;
  timestamp: string | null;
}

@Injectable()
export class DashboardService {
  constructor(
    @InjectRepository(Agent)
    private readonly agentsRepo: Repository<Agent>,
    @InjectRepository(AgentHeartbeat)
    private readonly heartbeatsRepo: Repository<AgentHeartbeat>,
    @InjectRepository(Metric)
    private readonly metricsRepo: Repository<Metric>,
  ) {}

  async summary(tenantId?: string | null): Promise<DashboardSummary> {
    const where = tenantId ? { tenantId } : {};
    const agents = await this.agentsRepo.find({ where });
    const totalAgents = agents.length;
    const onlineAgents = agents.filter((a) => a.status === 'online').length;
    const offlineAgents = agents.filter((a) => a.status === 'offline').length;
    const unknownAgents = totalAgents - onlineAgents - offlineAgents;

    const totalMemoryBytes = agents.reduce(
      (acc, a) => acc + (Number(a.totalMemoryBytes) || 0),
      0,
    );
    const totalDiskBytes = agents.reduce(
      (acc, a) => acc + (Number(a.totalDiskBytes) || 0),
      0,
    );

    const latest = await this.latestMetricPerAgent(tenantId);
    const fleet = [...latest.values()];
    const avg = (key: 'cpuPercent' | 'memoryPercent' | 'diskPercent') =>
      fleet.length
        ? fleet.reduce((sum, m) => sum + Number(m[key] ?? 0), 0) / fleet.length
        : 0;

    return {
      totalAgents,
      onlineAgents,
      offlineAgents,
      unknownAgents,
      avgCpu: round(avg('cpuPercent')),
      avgMemory: round(avg('memoryPercent')),
      avgDisk: round(avg('diskPercent')),
      totalMemoryBytes,
      totalDiskBytes,
      lastUpdatedAt: new Date().toISOString(),
    };
  }

  async activityTrend(
    days: number,
    tenantId?: string | null,
  ): Promise<ActivityTrendPoint[]> {
    const safeDays = Math.max(1, Math.min(days, 90));
    const since = new Date();
    since.setUTCHours(0, 0, 0, 0);
    since.setUTCDate(since.getUTCDate() - (safeDays - 1));

    const qb = this.heartbeatsRepo
      .createQueryBuilder('h')
      .select(`date_trunc('day', h.timestamp)`, 'day')
      .addSelect('COUNT(*)', 'count')
      .addSelect('COUNT(DISTINCT h."agentId")', 'agents')
      .where('h.timestamp >= :since', { since })
      .groupBy('day')
      .orderBy('day', 'ASC');

    if (tenantId) {
      qb.andWhere(
        'h.agentId IN (SELECT a."agentId" FROM agents a WHERE a."tenantId" = :tenantId)',
        { tenantId },
      );
    }

    const rows: Array<{ day: string; count: string; agents: string }> =
      await qb.getRawMany();

    const byDay = new Map<string, { heartbeats: number; agents: number }>();
    for (const r of rows) {
      const key = new Date(r.day).toISOString().slice(0, 10);
      byDay.set(key, {
        heartbeats: parseInt(r.count, 10) || 0,
        agents: parseInt(r.agents, 10) || 0,
      });
    }

    const out: ActivityTrendPoint[] = [];
    for (let i = 0; i < safeDays; i++) {
      const d = new Date(since);
      d.setUTCDate(since.getUTCDate() + i);
      const key = d.toISOString().slice(0, 10);
      const v = byDay.get(key);
      out.push({
        date: key,
        heartbeats: v?.heartbeats ?? 0,
        agents: v?.agents ?? 0,
      });
    }
    return out;
  }

  async osDistribution(tenantId?: string | null): Promise<OsDistributionEntry[]> {
    const qb = this.agentsRepo
      .createQueryBuilder('a')
      .select(`COALESCE(a.os, 'unknown')`, 'os')
      .addSelect('COUNT(*)', 'count')
      .groupBy('a.os');

    if (tenantId) qb.where('a."tenantId" = :tenantId', { tenantId });

    const rows: Array<{ os: string | null; count: string }> = await qb.getRawMany();

    return rows
      .map((r) => ({
        os: (r.os || 'unknown').toLowerCase(),
        count: parseInt(r.count, 10) || 0,
      }))
      .sort((a, b) => b.count - a.count);
  }

  async cpuByAgent(
    limit: number,
    tenantId?: string | null,
  ): Promise<CpuByAgentEntry[]> {
    const safe = Math.max(1, Math.min(limit, 50));
    const latest = await this.latestMetricPerAgent(tenantId);
    const where = tenantId ? { tenantId } : {};
    const agents = await this.agentsRepo.find({ where });
    const byId = new Map(agents.map((a) => [a.agentId, a]));

    const items: CpuByAgentEntry[] = [];
    for (const [agentId, m] of latest) {
      const a = byId.get(agentId);
      if (!a) continue;
      items.push({
        agentId,
        hostname: a.hostname || agentId.slice(0, 8),
        os: a.os ?? null,
        cpuPercent: round(Number(m.cpuPercent) || 0),
        memoryPercent: round(Number(m.memoryPercent) || 0),
        diskPercent: round(Number(m.diskPercent) || 0),
        status: a.status,
        timestamp: m.timestamp ? new Date(m.timestamp).toISOString() : null,
      });
    }
    items.sort((a, b) => b.cpuPercent - a.cpuPercent);
    return items.slice(0, safe);
  }

  private async latestMetricPerAgent(
    tenantId?: string | null,
  ): Promise<Map<string, Metric>> {
    const sql = tenantId
      ? `SELECT DISTINCT ON (m."agentId") m.*
           FROM "metrics" m
           JOIN "agents" a ON a."agentId" = m."agentId"
          WHERE a."tenantId" = $1
          ORDER BY m."agentId", m."timestamp" DESC`
      : `SELECT DISTINCT ON ("agentId") *
           FROM "metrics"
          ORDER BY "agentId", "timestamp" DESC`;
    const rows: Metric[] = tenantId
      ? await this.metricsRepo.query(sql, [tenantId])
      : await this.metricsRepo.query(sql);
    const map = new Map<string, Metric>();
    for (const r of rows) map.set(r.agentId, r);
    return map;
  }
}

function round(n: number, p = 1) {
  const f = Math.pow(10, p);
  return Math.round((n + Number.EPSILON) * f) / f;
}
