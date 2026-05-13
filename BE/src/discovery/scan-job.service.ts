import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Cron } from '@nestjs/schedule';
import { DataSource, LessThan, Repository } from 'typeorm';
import { ScanJob, ScanJobPillar, ScanJobStatus } from './entities/scan-job.entity';
import { DiscoverySession } from './entities/discovery-session.entity';
import { Observation } from './entities/observation.entity';
import { AuditLogService } from './audit-log.service';

/**
 * How long a job is allowed to sit in `assigned` or `running` before the
 * sweeper declares it dead. Tuned for the longest pillar we expect — a
 * full SNMP crawl on a 100-device site lands well inside 10 minutes; we
 * use 20 to keep operator-visible "stuck job" alerts rare.
 */
const SCAN_JOB_STALE_MS = 20 * 60 * 1000;

/** Postgres NOTIFY channel used to wake the dispatcher on insert. */
export const SCAN_JOB_NOTIFY_CHANNEL = 'disc_scan_job_new';

/**
 * Owns the scan-job lifecycle. For Chapter 0 we only implement create, list,
 * and the `pillar=noop` simulator that round-trips through session +
 * observation rows. The real WS-based collector pickup arrives once the
 * Go collector skeleton grows real pillars (Chapter 1+).
 */
@Injectable()
export class ScanJobService {
  private readonly logger = new Logger(ScanJobService.name);

  constructor(
    @InjectRepository(ScanJob)
    private readonly jobs: Repository<ScanJob>,
    @InjectRepository(DiscoverySession)
    private readonly sessions: Repository<DiscoverySession>,
    @InjectRepository(Observation)
    private readonly observations: Repository<Observation>,
    private readonly audit: AuditLogService,
    private readonly dataSource: DataSource,
  ) {}

  async create(input: {
    tenantId: string;
    actor: string;
    pillar: ScanJobPillar;
    collectorId?: string | null;
    targetSpec?: Record<string, unknown>;
    credentialRefs?: string[];
  }): Promise<ScanJob> {
    const row = this.jobs.create({
      tenantId: input.tenantId,
      collectorId: input.collectorId ?? null,
      pillar: input.pillar,
      targetSpec: input.targetSpec ?? {},
      credentialRefs: input.credentialRefs ?? [],
      status: 'queued',
    });
    const saved = await this.jobs.save(row);

    await this.audit.write({
      tenantId: input.tenantId,
      actor: input.actor,
      action: 'scan.created',
      entityKind: 'scan_job',
      entityId: saved.id,
      metadata: { pillar: input.pillar, collectorId: input.collectorId ?? null },
    });

    // Wake the dispatcher service. Payload is just the job id (Postgres
    // NOTIFY truncates above 8 KiB and we don't need anything else —
    // the dispatcher SELECTs the row to read the rest).
    //
    // `NOTIFY` is a Postgres utility command, not a query, so the
    // wire-protocol bind step doesn't apply — `$1` is a syntax error
    // there. Use `pg_notify(channel, payload)` instead; it's a regular
    // function and accepts parameter binding normally.
    await this.dataSource.query(`SELECT pg_notify($1, $2)`, [
      SCAN_JOB_NOTIFY_CHANNEL,
      saved.id,
    ]);
    return saved;
  }

  async markRunning(id: string, collectorId: string): Promise<void> {
    await this.jobs.update(
      { id },
      { status: 'running' as ScanJobStatus, collectorId, statusReason: null },
    );
  }

  async markCompleted(
    id: string,
    sessionId: string,
    observationCount: number,
  ): Promise<void> {
    await this.dataSource.transaction(async (em) => {
      await em.update(
        ScanJob,
        { id },
        {
          status: 'completed' as ScanJobStatus,
          resultSessionId: sessionId,
          statusReason: `observations=${observationCount}`,
        },
      );
      await em.update(
        DiscoverySession,
        { id: sessionId },
        { endedAt: new Date(), observationCount },
      );
    });
  }

  async markFailed(
    id: string,
    reason: string,
    detail: string | null,
  ): Promise<void> {
    const text = detail ? `${reason}: ${detail}` : reason;
    await this.jobs.update(
      { id },
      { status: 'failed' as ScanJobStatus, statusReason: text.slice(0, 1024) },
    );
  }

  /**
   * Stale-job sweeper — chapter-0 exit checklist. A collector that dies
   * mid-walk leaves its row stuck in `running`. Every minute we flip any
   * row older than SCAN_JOB_STALE_MS to `timeout` so the dashboard
   * surfaces a clear failure instead of an indefinite spinner.
   *
   * We update by `updatedAt` (not createdAt) so a long-running but
   * actively-progressing job — every chunk bumps updatedAt via
   * markRunning/markCompleted — isn't killed mid-flight.
   */
  @Cron('0 * * * * *') // every minute at the top of the second
  async sweepStaleJobs(): Promise<void> {
    const cutoff = new Date(Date.now() - SCAN_JOB_STALE_MS);
    const stale = await this.jobs.find({
      where: [
        { status: 'running' as ScanJobStatus, updatedAt: LessThan(cutoff) },
        { status: 'assigned' as ScanJobStatus, updatedAt: LessThan(cutoff) },
      ],
      take: 100,
    });
    if (stale.length === 0) return;
    this.logger.warn(`sweeping ${stale.length} stale scan job(s)`);
    for (const job of stale) {
      await this.jobs.update(
        { id: job.id },
        {
          status: 'timeout' as ScanJobStatus,
          statusReason: 'no progress within stale timeout — collector may have died',
        },
      );
      await this.audit.write({
        tenantId: job.tenantId,
        actor: 'sweeper',
        action: 'scan.timeout',
        entityKind: 'scan_job',
        entityId: job.id,
        metadata: {
          previousStatus: job.status,
          collectorId: job.collectorId,
          ageMs: Date.now() - new Date(job.updatedAt).getTime(),
        },
      });
    }
  }

  async list(tenantId: string, limit = 50): Promise<ScanJob[]> {
    return this.jobs.find({
      where: { tenantId },
      order: { createdAt: 'DESC' },
      take: limit,
    });
  }

  async getOne(tenantId: string, id: string): Promise<ScanJob> {
    const row = await this.jobs.findOneBy({ id, tenantId });
    if (!row) throw new NotFoundException('scan job not found');
    return row;
  }

  /**
   * Chapter-0 end-to-end proof. Takes a queued `noop` job, runs the simulator
   * inline (no collector required), and produces one session row + one
   * observation row. Demonstrates that the data layer + tenant scoping work
   * before any actual scanning code exists.
   */
  async simulateNoop(input: {
    tenantId: string;
    actor: string;
    jobId: string;
    collectorId?: string;
  }): Promise<{ sessionId: string; observationId: string }> {
    const job = await this.getOne(input.tenantId, input.jobId);
    if (job.pillar !== 'noop') {
      throw new Error(`simulateNoop expects pillar=noop, got pillar=${job.pillar}`);
    }
    const collectorId = input.collectorId ?? job.collectorId ?? randomCollectorId();

    return this.dataSource.transaction(async (em) => {
      await em.update(ScanJob, { id: job.id }, { status: 'running' as ScanJobStatus });

      const session = em.create(DiscoverySession, {
        tenantId: input.tenantId,
        scanJobId: job.id,
        collectorId,
        pillar: 'noop',
        endedAt: null,
        observationCount: 0,
      });
      const savedSession = await em.save(session);

      const observation = em.create(Observation, {
        tenantId: input.tenantId,
        sessionId: savedSession.id,
        collectorId,
        subjectKind: 'sentinel',
        subjectKey: 'noop',
        attribute: 'echo',
        value: { ok: true, jobId: job.id, ts: new Date().toISOString() },
        seenAt: new Date(),
      });
      const savedObs = await em.save(observation);

      await em.update(
        DiscoverySession,
        { id: savedSession.id },
        { endedAt: new Date(), observationCount: 1 },
      );
      await em.update(
        ScanJob,
        { id: job.id },
        { status: 'completed' as ScanJobStatus, resultSessionId: savedSession.id },
      );

      return { sessionId: savedSession.id, observationId: savedObs.id };
    });
  }
}

function randomCollectorId(): string {
  // For the simulator only — real collectors register themselves and carry
  // a stable id baked into their binary (mirroring the agent flow).
  return '00000000-0000-0000-0000-000000000000';
}
