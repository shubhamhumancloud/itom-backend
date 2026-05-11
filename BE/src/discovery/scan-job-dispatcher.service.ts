import {
  Injectable,
  Logger,
  OnApplicationShutdown,
  OnModuleInit,
} from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import { Client as PgClient } from 'pg';
import { ScanJob, ScanJobStatus } from './entities/scan-job.entity';
import { Collector } from './entities/collector.entity';
import { CollectorService } from './collector.service';
import { DiscoveryGateway } from './ws/discovery.gateway';
import { SigningService } from './signing.service';
import { ObservationIngestService } from './observation-ingest.service';
import { AuditLogService } from './audit-log.service';
import { SCAN_JOB_NOTIFY_CHANNEL } from './scan-job.service';
import { Frame, ScanJobAssignPayload } from './ws/protocol';

/**
 * The bridge between Postgres NOTIFY and the WS gateway.
 *
 * Lifecycle:
 *   1. On boot: open a dedicated pg connection, LISTEN on
 *      `disc_scan_job_new`.
 *   2. On insert: ScanJobService NOTIFYs with `payload = jobId`.
 *   3. We SELECT ... FOR UPDATE SKIP LOCKED to claim the row (so
 *      multi-replica BE doesn't fight over the same job).
 *   4. Resolve target collector, build a signed ScanJobAssign, push it
 *      over the gateway. If the collector is offline, leave the row
 *      `queued` — a periodic sweep retries.
 *
 * Why a separate pg.Client?
 *   The TypeORM pool checks connections in/out; LISTEN needs to hold
 *   one open for the lifetime of the process. Sharing the pool would
 *   either pin a pooled connection forever (starvation) or lose
 *   notifications between checkouts.
 */
@Injectable()
export class ScanJobDispatcherService
  implements OnModuleInit, OnApplicationShutdown
{
  private readonly logger = new Logger(ScanJobDispatcherService.name);
  private listenClient!: PgClient;
  private sweepTimer?: NodeJS.Timeout;

  constructor(
    @InjectDataSource()
    private readonly dataSource: DataSource,
    @InjectRepository(ScanJob)
    private readonly jobs: Repository<ScanJob>,
    @InjectRepository(Collector)
    private readonly collectors: Repository<Collector>,
    private readonly collectorService: CollectorService,
    private readonly gateway: DiscoveryGateway,
    private readonly signing: SigningService,
    private readonly sessions: ObservationIngestService,
    private readonly audit: AuditLogService,
  ) {}

  async onModuleInit() {
    await this.openListener();
    // Catch-up sweep: every 15s, scan for queued jobs whose targeted
    // collector has since come online and dispatch them. Covers the
    // "job inserted while collector was offline" case without forcing
    // an explicit re-poke from the dashboard.
    this.sweepTimer = setInterval(() => {
      this.sweepQueued().catch((e) =>
        this.logger.warn(`queued sweep failed: ${e.message}`),
      );
    }, 15_000);
  }

  async onApplicationShutdown() {
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    try {
      await this.listenClient?.end();
    } catch {
      /* noop */
    }
  }

  private async openListener() {
    const opts = this.dataSource.options as any;
    this.listenClient = new PgClient({
      host: opts.host,
      port: opts.port,
      user: opts.username,
      password: opts.password,
      database: opts.database,
    });
    await this.listenClient.connect();
    await this.listenClient.query(`LISTEN ${SCAN_JOB_NOTIFY_CHANNEL}`);
    this.listenClient.on('notification', (msg) => {
      if (msg.channel !== SCAN_JOB_NOTIFY_CHANNEL || !msg.payload) return;
      this.dispatch(msg.payload).catch((e) =>
        this.logger.error(`dispatch ${msg.payload} failed: ${e.message}`),
      );
    });
    this.listenClient.on('error', (err) =>
      this.logger.error(`pg listen client error: ${err.message}`),
    );
    this.logger.log(`LISTENing on ${SCAN_JOB_NOTIFY_CHANNEL}`);
  }

  /**
   * Claim and dispatch one job. The SKIP LOCKED query is the
   * coordination primitive: if two BE replicas LISTEN on the same
   * channel, only one gets the row.
   */
  private async dispatch(jobId: string): Promise<void> {
    const claimed = await this.dataSource.transaction(async (em) => {
      // Lock + flip to `assigned` atomically. Anyone else trying to
      // claim the same row will get nothing back.
      const rows = await em.query(
        `
          UPDATE disc_scan_job
          SET status = 'assigned', updated_at = now()
          WHERE id = $1
            AND status = 'queued'
            AND id IN (
              SELECT id FROM disc_scan_job
              WHERE id = $1 AND status = 'queued'
              FOR UPDATE SKIP LOCKED
            )
          RETURNING *
        `,
        [jobId],
      );
      return rows[0] as ScanJob | undefined;
    });
    if (!claimed) {
      // Either already taken or no longer queued. Either way: no-op.
      return;
    }
    await this.assignToCollector(claimed);
  }

  /**
   * Send ScanJobAssign to the target collector. If no specific collector
   * was targeted, pick any online one for the tenant.
   */
  private async assignToCollector(job: ScanJob): Promise<void> {
    let collector: Collector | null = null;
    if (job.collectorId) {
      collector = await this.collectors.findOneBy({ id: job.collectorId });
    } else {
      // Any online collector belonging to the tenant.
      collector = await this.collectors.findOne({
        where: { tenantId: job.tenantId, status: 'online' },
        order: { lastSeenAt: 'DESC' },
      });
    }
    if (!collector || !this.gateway.isConnected(collector.id)) {
      // Park: leave row `queued` so the sweep retries when the
      // collector comes back. Reverting status because a row stuck in
      // `assigned` would block legit retries.
      await this.jobs.update(
        { id: job.id },
        { status: 'queued' as ScanJobStatus, statusReason: 'awaiting online collector' },
      );
      this.logger.log(
        `job ${job.id} parked — collector ${collector?.id ?? '<none>'} not online`,
      );
      return;
    }

    // Always create the session row up-front; the collector references
    // its id in every chunk.
    const session = await this.sessions.createSession({
      tenantId: job.tenantId,
      scanJobId: job.id,
      collectorId: collector.id,
      pillar: job.pillar,
    });

    const { signature, cidrs } = this.signing.signAllowlist(collector.allowedCidrs ?? []);

    const targetSpec = (job.targetSpec ?? {}) as Record<string, unknown>;
    const vendor = (targetSpec['vendor'] as string | undefined) ?? '';

    const assign: ScanJobAssignPayload = {
      jobId: job.id,
      sessionId: session.id,
      tenantId: job.tenantId,
      pillar: job.pillar,
      vendor: vendor as ScanJobAssignPayload['vendor'],
      targetSpec,
      credentialIds: job.credentialRefs ?? [],
      allowlistCidrs: cidrs,
      allowlistSignature: signature,
    };
    const frame: Frame<ScanJobAssignPayload> = {
      kind: 'scan_job.assign',
      payload: assign,
    };
    const sent = this.gateway.sendTo(collector.id, frame);
    if (!sent) {
      // Race: collector dropped between isConnected and sendTo. Park.
      await this.jobs.update(
        { id: job.id },
        { status: 'queued' as ScanJobStatus, statusReason: 'collector disconnected at send' },
      );
      return;
    }
    await this.audit.write({
      tenantId: job.tenantId,
      actor: 'dispatcher',
      action: 'scan.assigned',
      entityKind: 'scan_job',
      entityId: job.id,
      metadata: { collectorId: collector.id, sessionId: session.id, vendor },
    });
  }

  /**
   * Re-attempt every job currently parked in `queued` whose collector
   * is now online. Runs every 15s; cheap (one SELECT + a few NOTIFYs).
   */
  private async sweepQueued(): Promise<void> {
    const queued = await this.jobs.find({
      where: { status: 'queued' as ScanJobStatus },
      take: 50,
      order: { createdAt: 'ASC' },
    });
    for (const job of queued) {
      // Re-emit a NOTIFY for this row so the same dispatch path runs
      // — keeps the assignment logic in one place.
      await this.dataSource.query(
        `NOTIFY ${SCAN_JOB_NOTIFY_CHANNEL}, $1`,
        [job.id],
      );
    }
  }
}
