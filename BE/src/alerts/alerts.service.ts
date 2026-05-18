import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, IsNull, Repository } from 'typeorm';
import { AlertRule, AlertCategory, AlertMetric } from './entities/alert-rule.entity';
import { Alert } from './entities/alert.entity';
import { Incident } from './entities/incident.entity';
import { IncidentEvent } from './entities/incident-event.entity';
import { Agent } from '../agents/agent.entity';
import { Metric } from '../metrics/metric.entity';

/**
 * Where a scoped metric rule reads from. Each entry maps a rule `metric`
 * to a table + value column, an optional per-scope grouping column, and an
 * optional row filter. `net_throughput`, `agent_offline` and
 * `agent_flapping` are handled by dedicated evaluators, not this table.
 */
type MetricSource = {
  table: string;
  valueColumn: string;
  /** Column the alert scopes on (mountpoint / gpuIndex / …). null = host. */
  scopeColumn: string | null;
  /** Prefix prepended to the scope value, e.g. `gpu:` → `gpu:0`. */
  scopePrefix?: string;
  /** Extra SQL predicate, e.g. `kind = 'temperature_c'`. */
  extraWhere?: string;
};

const METRIC_SOURCES: Partial<Record<AlertMetric, MetricSource>> = {
  cpu: { table: 'metrics', valueColumn: 'cpuPercent', scopeColumn: null },
  memory: { table: 'metrics', valueColumn: 'memoryPercent', scopeColumn: null },
  battery: { table: 'battery_metrics', valueColumn: 'percent', scopeColumn: null },
  disk: {
    table: 'disk_metrics',
    valueColumn: 'usedPercent',
    scopeColumn: 'mountpoint',
  },
  gpu_temp: {
    table: 'gpu_metrics',
    valueColumn: 'temperatureC',
    scopeColumn: 'gpuIndex',
    scopePrefix: 'gpu:',
  },
  cpu_temp: {
    table: 'sensor_metrics',
    valueColumn: 'value',
    scopeColumn: 'name',
    extraWhere: "kind = 'temperature_c'",
  },
  process_cpu: {
    table: 'process_metrics',
    valueColumn: 'cpuPercent',
    scopeColumn: 'processName',
  },
};

/** Display unit appended to a metric value in alert messages. */
const METRIC_UNIT: Partial<Record<AlertMetric, string>> = {
  cpu: '%',
  memory: '%',
  disk: '%',
  battery: '%',
  process_cpu: '%',
  gpu_temp: '°C',
  cpu_temp: '°C',
  net_throughput: ' Mbps',
};

const CATEGORY_LABEL: Record<string, string> = {
  compute: 'Compute',
  storage: 'Storage',
  thermal: 'Thermal',
  power: 'Power',
  network: 'Network',
  availability: 'Availability',
  process: 'Process',
};

/** A breach must show at least this many samples — guards against a lone
 *  transient reading firing a "sustained" rule. */
const MIN_SAMPLES = 3;

/** Sliding window for flap detection. */
const FLAP_WINDOW_MS = 30 * 60 * 1000;

/** One aggregated metric reading for a single (agent, scope) pair. */
type ScopedSample = {
  agentId: string;
  scopeKey: string;
  /** Worst-case value across the window (MIN for `gte`, MAX for `lt`). */
  agg: number;
  /** Most recent value — drives display + hysteresis recovery. */
  latest: number;
  count: number;
};

/** A built-in rule definition, seeded once and kept up to date by `key`. */
type RuleSeed = {
  key: string;
  name: string;
  metric: AlertMetric;
  category: AlertCategory;
  comparator: 'gte' | 'lt';
  warningThreshold: number | null;
  criticalThreshold: number | null;
  recoveryThreshold: number | null;
  forSeconds: number;
  enabled: boolean;
};

const DEFAULT_RULES: RuleSeed[] = [
  { key: 'builtin-cpu', name: 'High CPU utilisation', metric: 'cpu', category: 'compute', comparator: 'gte', warningThreshold: 85, criticalThreshold: 95, recoveryThreshold: 75, forSeconds: 300, enabled: true },
  { key: 'builtin-memory', name: 'High memory utilisation', metric: 'memory', category: 'compute', comparator: 'gte', warningThreshold: 85, criticalThreshold: 95, recoveryThreshold: 80, forSeconds: 300, enabled: true },
  { key: 'builtin-disk', name: 'Disk almost full', metric: 'disk', category: 'storage', comparator: 'gte', warningThreshold: 80, criticalThreshold: 90, recoveryThreshold: 78, forSeconds: 600, enabled: true },
  { key: 'builtin-gpu-temp', name: 'GPU overheating', metric: 'gpu_temp', category: 'thermal', comparator: 'gte', warningThreshold: 85, criticalThreshold: 95, recoveryThreshold: 80, forSeconds: 180, enabled: true },
  { key: 'builtin-cpu-temp', name: 'System temperature high', metric: 'cpu_temp', category: 'thermal', comparator: 'gte', warningThreshold: 80, criticalThreshold: 90, recoveryThreshold: 75, forSeconds: 180, enabled: true },
  { key: 'builtin-battery', name: 'Battery critically low', metric: 'battery', category: 'power', comparator: 'lt', warningThreshold: 20, criticalThreshold: 10, recoveryThreshold: 25, forSeconds: 300, enabled: true },
  { key: 'builtin-process-cpu', name: 'Runaway process', metric: 'process_cpu', category: 'process', comparator: 'gte', warningThreshold: 90, criticalThreshold: null, recoveryThreshold: 80, forSeconds: 600, enabled: true },
  { key: 'builtin-network', name: 'Network throughput sustained high', metric: 'net_throughput', category: 'network', comparator: 'gte', warningThreshold: 500, criticalThreshold: 800, recoveryThreshold: 400, forSeconds: 300, enabled: false },
  { key: 'builtin-offline', name: 'Agent offline', metric: 'agent_offline', category: 'availability', comparator: 'gte', warningThreshold: null, criticalThreshold: null, recoveryThreshold: null, forSeconds: 0, enabled: true },
  { key: 'builtin-flapping', name: 'Agent connection flapping', metric: 'agent_flapping', category: 'availability', comparator: 'gte', warningThreshold: 4, criticalThreshold: null, recoveryThreshold: null, forSeconds: 0, enabled: true },
];

@Injectable()
export class AlertsService implements OnModuleInit {
  private readonly logger = new Logger(AlertsService.name);

  constructor(
    @InjectRepository(AlertRule)
    private readonly ruleRepo: Repository<AlertRule>,
    @InjectRepository(Alert)
    private readonly alertRepo: Repository<Alert>,
    @InjectRepository(Incident)
    private readonly incidentRepo: Repository<Incident>,
    @InjectRepository(IncidentEvent)
    private readonly eventRepo: Repository<IncidentEvent>,
    @InjectRepository(Agent)
    private readonly agentRepo: Repository<Agent>,
    @InjectRepository(Metric)
    private readonly metricRepo: Repository<Metric>,
  ) {}

  /** Raw SQL helper — `Repository.query` runs against the whole connection. */
  private query<T = unknown>(sql: string, params: unknown[] = []): Promise<T[]> {
    return this.metricRepo.query(sql, params) as Promise<T[]>;
  }

  // ───────────────────────── Rule seeding ────────────────────────

  /**
   * Seed (and adopt) the built-in rule set. Idempotent and upgrade-safe:
   *  - a rule already keyed → left untouched (respects user edits),
   *  - a legacy keyless global rule of the same metric → adopted (keyed),
   *  - otherwise → inserted fresh.
   */
  async onModuleInit(): Promise<void> {
    let created = 0;
    for (const seed of DEFAULT_RULES) {
      const keyed = await this.ruleRepo.findOne({ where: { key: seed.key } });
      if (keyed) continue;

      const legacy = await this.ruleRepo.findOne({
        where: { tenantId: IsNull(), metric: seed.metric, key: IsNull() },
      });
      if (legacy) {
        legacy.key = seed.key;
        await this.ruleRepo.save(legacy);
        continue;
      }

      await this.ruleRepo.save(this.ruleRepo.create({ ...seed, tenantId: null }));
      created++;
    }
    if (created > 0) this.logger.log(`seeded ${created} default alert rule(s)`);
  }

  // ───────────────────────── Evaluation ──────────────────────────

  /**
   * One evaluation pass. For every enabled rule, picks the agents it
   * applies to (honouring tenant overrides) and transitions alert state.
   * Called by the cron in AlertsEvaluatorService (~every 60s).
   */
  async runEvaluation(): Promise<void> {
    const rules = await this.ruleRepo.find({ where: { enabled: true } });
    if (rules.length === 0) return;
    const agents = await this.agentRepo.find();
    if (agents.length === 0) return;

    // A tenant rule for metric M shadows the global rule for M — for that
    // tenant's agents only. Pre-index those (tenant, metric) pairs.
    const overrides = new Set(
      rules
        .filter((r) => r.tenantId)
        .map((r) => `${r.tenantId}|${r.metric}`),
    );

    for (const rule of rules) {
      const scope = agents.filter((a) =>
        rule.tenantId
          ? a.tenantId === rule.tenantId
          : !(a.tenantId && overrides.has(`${a.tenantId}|${rule.metric}`)),
      );
      if (scope.length === 0) continue;

      try {
        switch (rule.metric) {
          case 'agent_offline':
            await this.evalOfflineRule(rule, scope);
            break;
          case 'agent_flapping':
            await this.evalFlappingRule(rule, scope);
            break;
          case 'net_throughput':
            await this.evalNetworkRule(rule, scope);
            break;
          default:
            await this.evalScopedRule(rule, scope);
        }
      } catch (err) {
        this.logger.error(`rule "${rule.name}" failed: ${String(err)}`);
      }
    }
  }

  /** Generic table-backed rule (cpu/memory/disk/gpu_temp/cpu_temp/battery/process). */
  private async evalScopedRule(rule: AlertRule, agents: Agent[]): Promise<void> {
    const samples = await this.fetchScopedSamples(rule);
    const agentById = new Map(agents.map((a) => [a.agentId, a]));
    for (const s of samples) {
      const agent = agentById.get(s.agentId);
      if (!agent) continue; // out of this rule's tenant scope
      const dedupKey = `${rule.id}:${s.agentId}:${s.scopeKey}`;
      await this.transition(rule, agent, s.scopeKey, dedupKey, s);
    }
  }

  /** Run one (agent, scope) sample through the firing/resolved state machine. */
  private async transition(
    rule: AlertRule,
    agent: Agent,
    scopeKey: string,
    dedupKey: string,
    s: ScopedSample,
  ): Promise<void> {
    const existing = await this.alertRepo.findOne({
      where: { dedupKey, state: 'firing' },
    });

    // A breach needs enough samples to count as "sustained". A firing
    // alert with thin data is held (no flip-flop), not freshly created.
    const { severity, threshold } =
      s.count >= MIN_SAMPLES
        ? this.classify(rule, s.agg)
        : { severity: null as 'warning' | 'critical' | null, threshold: null };

    if (severity) {
      if (!existing) {
        await this.openAlert(rule, agent, scopeKey, dedupKey, severity, threshold, s.latest);
        return;
      }
      existing.metricValue = s.latest;
      existing.lastEvaluatedAt = new Date();
      if (existing.severity !== severity) {
        const old = existing.severity;
        existing.severity = severity;
        existing.threshold = threshold;
        existing.message = this.alertMessage(rule, severity, s.latest, scopeKey);
        await this.alertRepo.save(existing);
        await this.onSeverityChange(existing, old);
      } else {
        await this.alertRepo.save(existing);
      }
      return;
    }

    if (existing) {
      // Hysteresis: only resolve once the latest value clears the recovery
      // band; in the gap between recovery and breach we hold it firing.
      if (this.hasRecovered(rule, s.latest)) {
        await this.resolveAlert(existing, s.latest);
      } else {
        existing.metricValue = s.latest;
        existing.lastEvaluatedAt = new Date();
        await this.alertRepo.save(existing);
      }
    }
  }

  /**
   * Pull one aggregated reading per (agent, scope) from the rule's source
   * table. `agg` is MIN for `gte` rules / MAX for `lt` rules — i.e. the
   * worst sample, so a breach holds only if EVERY sample violated it.
   */
  private async fetchScopedSamples(rule: AlertRule): Promise<ScopedSample[]> {
    const src = METRIC_SOURCES[rule.metric];
    if (!src) return [];

    const since = new Date(Date.now() - Math.max(rule.forSeconds, 30) * 1000);
    const aggFn = rule.comparator === 'lt' ? 'MAX' : 'MIN';
    const scopeSel = src.scopeColumn ? `"${src.scopeColumn}"` : `''`;
    const extra = src.extraWhere ? `AND ${src.extraWhere}` : '';

    const aggRows = await this.query<{
      agentId: string;
      scope: string;
      agg: string | null;
      n: string;
    }>(
      `SELECT "agentId", ${scopeSel} AS scope,
              ${aggFn}("${src.valueColumn}") AS agg, COUNT(*) AS n
         FROM ${src.table}
        WHERE timestamp >= $1 ${extra}
        GROUP BY "agentId", ${scopeSel}`,
      [since],
    );

    const latestRows = await this.query<{
      agentId: string;
      scope: string;
      latest: string;
    }>(
      `SELECT DISTINCT ON ("agentId", ${scopeSel})
              "agentId", ${scopeSel} AS scope, "${src.valueColumn}" AS latest
         FROM ${src.table}
        WHERE timestamp >= $1 ${extra}
        ORDER BY "agentId", ${scopeSel}, timestamp DESC`,
      [since],
    );
    const latestByKey = new Map(
      latestRows.map((r) => [`${r.agentId}|${r.scope}`, Number(r.latest)]),
    );

    const out: ScopedSample[] = [];
    for (const r of aggRows) {
      if (r.agg == null) continue; // all-null column (e.g. GPU with no temp)
      const agg = Number(r.agg);
      out.push({
        agentId: r.agentId,
        scopeKey: src.scopePrefix
          ? `${src.scopePrefix}${r.scope}`
          : String(r.scope ?? ''),
        agg,
        latest: latestByKey.get(`${r.agentId}|${r.scope}`) ?? agg,
        count: Number(r.n),
      });
    }
    return out;
  }

  /** Per-interface throughput in Mbps, derived from byte-counter deltas. */
  private async evalNetworkRule(rule: AlertRule, agents: Agent[]): Promise<void> {
    const since = new Date(Date.now() - Math.max(rule.forSeconds, 120) * 1000);
    const rows = await this.query<{
      agentId: string;
      interfaceName: string;
      timestamp: string;
      bytesSent: string;
      bytesRecv: string;
    }>(
      `SELECT "agentId", "interfaceName", timestamp, "bytesSent", "bytesRecv"
         FROM network_metrics
        WHERE timestamp >= $1
        ORDER BY "agentId", "interfaceName", timestamp ASC`,
      [since],
    );

    const agentById = new Map(agents.map((a) => [a.agentId, a]));
    const groups = new Map<string, typeof rows>();
    for (const r of rows) {
      const k = `${r.agentId}|${r.interfaceName}`;
      (groups.get(k) ?? groups.set(k, []).get(k)!).push(r);
    }

    for (const [k, series] of groups) {
      const [agentId, iface] = k.split('|');
      const agent = agentById.get(agentId);
      if (!agent || series.length < 2) continue;

      const rates: number[] = [];
      for (let i = 1; i < series.length; i++) {
        const dt =
          (new Date(series[i].timestamp).getTime() -
            new Date(series[i - 1].timestamp).getTime()) /
          1000;
        if (dt <= 0) continue;
        const dRecv = Number(series[i].bytesRecv) - Number(series[i - 1].bytesRecv);
        const dSent = Number(series[i].bytesSent) - Number(series[i - 1].bytesSent);
        if (dRecv < 0 || dSent < 0) continue; // counter reset — discard
        rates.push(((dRecv + dSent) * 8) / dt / 1e6); // Mbps, both directions
      }
      if (rates.length < MIN_SAMPLES) continue;

      const dedupKey = `${rule.id}:${agentId}:${iface}`;
      await this.transition(rule, agent, iface, dedupKey, {
        agentId,
        scopeKey: iface,
        agg: Math.min(...rates),
        latest: rates[rates.length - 1],
        count: rates.length,
      });
    }
  }

  /** Availability rule — fires while an agent's status is `offline`. */
  private async evalOfflineRule(rule: AlertRule, agents: Agent[]): Promise<void> {
    for (const agent of agents) {
      const dedupKey = `${rule.id}:${agent.agentId}:`;
      const existing = await this.alertRepo.findOne({
        where: { dedupKey, state: 'firing' },
      });
      if (agent.status === 'offline') {
        if (!existing) {
          await this.openAlert(rule, agent, '', dedupKey, 'critical', null, 0);
        } else {
          existing.lastEvaluatedAt = new Date();
          await this.alertRepo.save(existing);
        }
      } else if (existing && agent.status === 'online') {
        await this.resolveAlert(existing, 0);
      }
    }
  }

  /**
   * Flap detection — fires a single warning when an agent crossed
   * online↔offline too many times in the trailing 30 minutes, instead of
   * a stream of connect/disconnect noise.
   */
  private async evalFlappingRule(rule: AlertRule, agents: Agent[]): Promise<void> {
    const since = new Date(Date.now() - FLAP_WINDOW_MS);
    const rows = await this.query<{ agentId: string; n: string }>(
      `SELECT "agentId", COUNT(*) AS n
         FROM agent_status_events
        WHERE "occurredAt" >= $1
        GROUP BY "agentId"`,
      [since],
    );
    const transitions = new Map(rows.map((r) => [r.agentId, Number(r.n)]));
    const limit = rule.warningThreshold ?? 4;

    for (const agent of agents) {
      const n = transitions.get(agent.agentId) ?? 0;
      const dedupKey = `${rule.id}:${agent.agentId}:`;
      const existing = await this.alertRepo.findOne({
        where: { dedupKey, state: 'firing' },
      });
      if (n >= limit) {
        if (!existing) {
          await this.openAlert(rule, agent, '', dedupKey, 'warning', limit, n);
        } else {
          existing.metricValue = n;
          existing.lastEvaluatedAt = new Date();
          await this.alertRepo.save(existing);
        }
      } else if (existing) {
        await this.resolveAlert(existing, n);
      }
    }
  }

  // ──────────────────── Alert state helpers ──────────────────────

  private classify(
    rule: AlertRule,
    value: number,
  ): { severity: 'warning' | 'critical' | null; threshold: number | null } {
    const breaches = (t: number | null): boolean =>
      t != null && (rule.comparator === 'lt' ? value <= t : value >= t);
    if (breaches(rule.criticalThreshold)) {
      return { severity: 'critical', threshold: rule.criticalThreshold };
    }
    if (breaches(rule.warningThreshold)) {
      return { severity: 'warning', threshold: rule.warningThreshold };
    }
    return { severity: null, threshold: null };
  }

  private hasRecovered(rule: AlertRule, value: number): boolean {
    if (rule.comparator === 'lt') {
      const r = rule.recoveryThreshold ?? rule.warningThreshold ?? Infinity;
      return value > r;
    }
    const r = rule.recoveryThreshold ?? rule.warningThreshold ?? -Infinity;
    return value < r;
  }

  private async openAlert(
    rule: AlertRule,
    agent: Agent,
    scopeKey: string,
    dedupKey: string,
    severity: 'warning' | 'critical',
    threshold: number | null,
    value: number,
  ): Promise<void> {
    const now = new Date();
    const incident = await this.ensureIncident(agent, rule.category, severity);
    const message = this.alertMessage(rule, severity, value, scopeKey);
    const alert = this.alertRepo.create({
      tenantId: agent.tenantId ?? null,
      ruleId: rule.id,
      ruleName: rule.name,
      metric: rule.metric,
      category: rule.category,
      agentId: agent.agentId,
      scopeKey,
      dedupKey,
      severity,
      state: 'firing',
      metricValue: value,
      threshold,
      message,
      firstFiredAt: now,
      lastEvaluatedAt: now,
      incidentId: incident.id,
    });
    await this.alertRepo.save(alert);

    incident.alertCount += 1;
    if (severity === 'critical') incident.severity = 'critical';
    await this.incidentRepo.save(incident);
    await this.logEvent(incident.id, 'alert_added', message, 'system');
    this.logger.warn(`alert FIRED — ${message} [agent=${agent.agentId}]`);
  }

  private async resolveAlert(alert: Alert, value: number): Promise<void> {
    alert.state = 'resolved';
    alert.resolvedAt = new Date();
    alert.lastEvaluatedAt = new Date();
    alert.metricValue = value;
    await this.alertRepo.save(alert);
    if (alert.incidentId) {
      await this.logEvent(
        alert.incidentId,
        'alert_resolved',
        `Alert recovered: ${alert.ruleName}`,
        'system',
      );
    }
    this.logger.log(`alert RESOLVED — ${alert.ruleName} [agent=${alert.agentId}]`);
  }

  private async onSeverityChange(alert: Alert, oldSeverity: string): Promise<void> {
    if (!alert.incidentId) return;
    await this.logEvent(
      alert.incidentId,
      'severity_changed',
      `${alert.ruleName}: ${oldSeverity} → ${alert.severity}`,
      'system',
    );
    if (alert.severity === 'critical') {
      await this.incidentRepo.update(
        { id: alert.incidentId },
        { severity: 'critical' },
      );
    }
  }

  /** Find the open incident for (agent, category) or open a new one. */
  private async ensureIncident(
    agent: Agent,
    category: AlertCategory,
    severity: 'warning' | 'critical',
  ): Promise<Incident> {
    const open = await this.incidentRepo.findOne({
      where: {
        agentId: agent.agentId,
        category,
        status: In(['open', 'acknowledged']),
      },
    });
    if (open) return open;

    const incident = this.incidentRepo.create({
      tenantId: agent.tenantId ?? null,
      agentId: agent.agentId,
      category,
      title: `${CATEGORY_LABEL[category] ?? category} issue on ${
        agent.hostname || agent.agentId
      }`,
      severity,
      status: 'open',
      alertCount: 0,
      openedAt: new Date(),
    });
    await this.incidentRepo.save(incident);
    await this.logEvent(
      incident.id,
      'opened',
      `Incident opened — ${category} category`,
      'system',
    );
    return incident;
  }

  private async logEvent(
    incidentId: string,
    type: string,
    message: string,
    actor: string | null,
  ): Promise<void> {
    await this.eventRepo.save(
      this.eventRepo.create({
        incidentId,
        type,
        message,
        actor,
        occurredAt: new Date(),
      }),
    );
  }

  private alertMessage(
    rule: AlertRule,
    severity: string,
    value: number,
    scopeKey: string,
  ): string {
    if (rule.metric === 'agent_offline') {
      return 'Agent is offline — no telemetry received';
    }
    if (rule.metric === 'agent_flapping') {
      return `Connection flapping — ${value} state changes in 30 min`;
    }
    const unit = METRIC_UNIT[rule.metric] ?? '';
    const where = scopeKey ? ` [${scopeKey}]` : '';
    return `${rule.name}${where} — ${value.toFixed(1)}${unit} (${severity})`;
  }

  // ──────────────────────── Read queries ─────────────────────────

  async listAlerts(
    tenantId: string | null,
    filters: { state?: string; severity?: string; agentId?: string },
  ): Promise<Alert[]> {
    const qb = this.alertRepo
      .createQueryBuilder('a')
      .orderBy('a.lastEvaluatedAt', 'DESC')
      .limit(300);
    if (tenantId) qb.andWhere('a.tenantId = :tenantId', { tenantId });
    if (filters.state) qb.andWhere('a.state = :state', { state: filters.state });
    if (filters.severity)
      qb.andWhere('a.severity = :severity', { severity: filters.severity });
    if (filters.agentId)
      qb.andWhere('a.agentId = :agentId', { agentId: filters.agentId });
    return qb.getMany();
  }

  async listIncidents(
    tenantId: string | null,
    status?: string,
  ): Promise<Array<Incident & { firingAlertCount: number }>> {
    const qb = this.incidentRepo
      .createQueryBuilder('i')
      .orderBy('i.openedAt', 'DESC')
      .limit(300);
    if (tenantId) qb.andWhere('i.tenantId = :tenantId', { tenantId });
    if (status) qb.andWhere('i.status = :status', { status });
    const incidents = await qb.getMany();
    if (incidents.length === 0) return [];

    const rows = await this.alertRepo
      .createQueryBuilder('a')
      .select('a.incidentId', 'incidentId')
      .addSelect('COUNT(*)', 'n')
      .where('a.state = :s', { s: 'firing' })
      .andWhere('a.incidentId IN (:...ids)', { ids: incidents.map((i) => i.id) })
      .groupBy('a.incidentId')
      .getRawMany<{ incidentId: string; n: string }>();
    const firing = new Map(rows.map((r) => [r.incidentId, parseInt(r.n, 10)]));

    return incidents.map((i) => ({
      ...i,
      firingAlertCount: firing.get(i.id) ?? 0,
    }));
  }

  async getIncident(id: string, tenantId: string | null) {
    const incident = await this.loadOwned(id, tenantId);
    if (!incident) return null;
    const alerts = await this.alertRepo.find({
      where: { incidentId: id },
      order: { firstFiredAt: 'DESC' },
    });
    const events = await this.eventRepo.find({
      where: { incidentId: id },
      order: { occurredAt: 'ASC' },
    });
    const firingAlertCount = alerts.filter((a) => a.state === 'firing').length;
    return {
      incident,
      alerts,
      events,
      firingAlertCount,
      readyToClose: incident.status !== 'resolved' && firingAlertCount === 0,
    };
  }

  /**
   * Effective rule set for a tenant — one row per metric: the tenant's
   * override if it has one, otherwise the global default.
   */
  async listRules(
    tenantId: string | null,
  ): Promise<Array<AlertRule & { scope: 'global' | 'tenant' }>> {
    const all = await this.ruleRepo.find({
      where: [{ tenantId: IsNull() }, ...(tenantId ? [{ tenantId }] : [])],
    });
    const byMetric = new Map<string, AlertRule>();
    for (const r of all.filter((r) => !r.tenantId)) byMetric.set(r.metric, r);
    for (const r of all.filter((r) => r.tenantId)) byMetric.set(r.metric, r);
    return [...byMetric.values()]
      .map((r) => ({
        ...r,
        scope: (r.tenantId ? 'tenant' : 'global') as 'global' | 'tenant',
      }))
      .sort(
        (a, b) =>
          a.category.localeCompare(b.category) ||
          a.metric.localeCompare(b.metric),
      );
  }

  // ─────────────────────── Rule management ───────────────────────

  /**
   * Update a rule's thresholds / window / enabled flag.
   *
   * A tenant editing a *global* rule does not mutate it (that would hit
   * every tenant) — it forks a tenant-scoped override. An admin with no
   * tenant context edits the global in place.
   */
  async updateRule(
    id: string,
    tenantId: string | null,
    patch: Partial<
      Pick<
        AlertRule,
        | 'warningThreshold'
        | 'criticalThreshold'
        | 'recoveryThreshold'
        | 'forSeconds'
        | 'enabled'
      >
    >,
  ): Promise<AlertRule | null> {
    const rule = await this.ruleRepo.findOne({ where: { id } });
    if (!rule) return null;

    const fields = this.pickRuleFields(patch);

    if (rule.tenantId) {
      if (tenantId && rule.tenantId !== tenantId) return null; // not yours
      Object.assign(rule, fields);
      return this.ruleRepo.save(rule);
    }

    // Editing a global rule.
    if (!tenantId) {
      Object.assign(rule, fields);
      return this.ruleRepo.save(rule);
    }

    // Tenant edit of a global rule → fork (or update) a tenant override.
    let override = await this.ruleRepo.findOne({
      where: { tenantId, metric: rule.metric },
    });
    if (!override) {
      override = this.ruleRepo.create({
        tenantId,
        key: null,
        name: rule.name,
        metric: rule.metric,
        category: rule.category,
        comparator: rule.comparator,
        warningThreshold: rule.warningThreshold,
        criticalThreshold: rule.criticalThreshold,
        recoveryThreshold: rule.recoveryThreshold,
        forSeconds: rule.forSeconds,
        enabled: rule.enabled,
      });
    }
    Object.assign(override, fields);
    return this.ruleRepo.save(override);
  }

  /** Drop a tenant override so the global default takes over again. */
  async resetRule(
    id: string,
    tenantId: string | null,
  ): Promise<{ reverted: boolean }> {
    const rule = await this.ruleRepo.findOne({ where: { id } });
    if (!rule || !rule.tenantId) return { reverted: false };
    if (tenantId && rule.tenantId !== tenantId) return { reverted: false };
    await this.ruleRepo.delete({ id });
    return { reverted: true };
  }

  private pickRuleFields(patch: Record<string, unknown>): Partial<AlertRule> {
    const out: Partial<AlertRule> = {};
    const num = (v: unknown): number | null =>
      v === null || v === undefined || v === '' ? null : Number(v);
    if ('warningThreshold' in patch) out.warningThreshold = num(patch.warningThreshold);
    if ('criticalThreshold' in patch)
      out.criticalThreshold = num(patch.criticalThreshold);
    if ('recoveryThreshold' in patch)
      out.recoveryThreshold = num(patch.recoveryThreshold);
    if ('forSeconds' in patch)
      out.forSeconds = Math.max(0, Number(patch.forSeconds) || 0);
    if ('enabled' in patch) out.enabled = Boolean(patch.enabled);
    return out;
  }

  // ─────────────────── Incident management ───────────────────────

  async acknowledgeIncident(id: string, tenantId: string | null, actor: string) {
    const incident = await this.loadOwned(id, tenantId);
    if (!incident) return null;
    if (incident.status === 'open') {
      incident.status = 'acknowledged';
      incident.acknowledgedAt = new Date();
      incident.acknowledgedBy = actor;
      await this.incidentRepo.save(incident);
      await this.logEvent(id, 'acknowledged', `Acknowledged by ${actor}`, actor);
    }
    return this.getIncident(id, tenantId);
  }

  async resolveIncident(id: string, tenantId: string | null, actor: string) {
    const incident = await this.loadOwned(id, tenantId);
    if (!incident) return null;
    if (incident.status !== 'resolved') {
      incident.status = 'resolved';
      incident.resolvedAt = new Date();
      incident.resolvedBy = actor;
      await this.incidentRepo.save(incident);
      await this.logEvent(id, 'resolved', `Resolved by ${actor}`, actor);
    }
    return this.getIncident(id, tenantId);
  }

  async commentIncident(
    id: string,
    tenantId: string | null,
    actor: string,
    message: string,
  ) {
    const incident = await this.loadOwned(id, tenantId);
    if (!incident) return null;
    await this.logEvent(id, 'comment', message, actor);
    return this.getIncident(id, tenantId);
  }

  private async loadOwned(
    id: string,
    tenantId: string | null,
  ): Promise<Incident | null> {
    const incident = await this.incidentRepo.findOne({ where: { id } });
    if (!incident) return null;
    if (tenantId && incident.tenantId && incident.tenantId !== tenantId) {
      return null;
    }
    return incident;
  }

  /** Counts for dashboard / sidebar badges. */
  async summary(tenantId: string | null) {
    const incidents = await this.listIncidents(tenantId);
    const open = incidents.filter((i) => i.status !== 'resolved');
    return {
      openIncidents: open.length,
      criticalIncidents: open.filter((i) => i.severity === 'critical').length,
      acknowledgedIncidents: open.filter((i) => i.status === 'acknowledged').length,
      firingAlerts: open.reduce((s, i) => s + i.firingAlertCount, 0),
    };
  }
}
