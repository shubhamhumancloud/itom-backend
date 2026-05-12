import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { Observation } from './entities/observation.entity';
import { DiscoverySession } from './entities/discovery-session.entity';
import { ScanJob } from './entities/scan-job.entity';
import { AuditLogService } from './audit-log.service';
import { ScanJobChunkPayload } from './ws/protocol';

/**
 * Observation attributes that classify a per-device failure. When the
 * collector emits one of these we mirror it to disc_audit_log so the
 * operator can grep audit for "credential broke" without trawling the
 * raw observation stream.
 */
const FAILURE_ATTRIBUTES = new Set([
  'auth_failed',
  'unreachable',
  'refused',
  'ingest_failed',
]);

/**
 * Batch-inserts observation rows from a ScanJobChunk and bumps the
 * session counter. The hot path: WS gateway → here → Postgres.
 *
 * We resolve tenantId from the session row keyed by sessionId (rather
 * than trusting whatever the collector sent in the chunk) so a buggy
 * or malicious collector cannot write observations under another
 * tenant's id.
 */
@Injectable()
export class ObservationIngestService {
  private readonly logger = new Logger(ObservationIngestService.name);

  constructor(
    @InjectRepository(Observation)
    private readonly observations: Repository<Observation>,
    @InjectRepository(DiscoverySession)
    private readonly sessions: Repository<DiscoverySession>,
    @InjectRepository(ScanJob)
    private readonly jobs: Repository<ScanJob>,
    private readonly audit: AuditLogService,
    private readonly dataSource: DataSource,
  ) {}

  async ingest(collectorId: string, chunk: ScanJobChunkPayload): Promise<void> {
    if (!chunk?.observations?.length) return;

    const session = await this.sessions.findOneBy({ id: chunk.sessionId });
    if (!session) {
      throw new NotFoundException(`session ${chunk.sessionId} not found`);
    }
    // Pin the collector_id on every row to the WS-authenticated one.
    // The chunk doesn't carry it (the session does), so we read it back
    // from the session — collectors can't lie about who they are.
    const tenantId = session.tenantId;
    const sessionCollectorId = session.collectorId;
    if (sessionCollectorId !== collectorId) {
      this.logger.warn(
        `collector ${collectorId} sent chunk for session belonging to ${sessionCollectorId}; rejecting`,
      );
      throw new Error('collector/session mismatch');
    }

    const rows = chunk.observations.map((o) => ({
      tenantId,
      sessionId: chunk.sessionId,
      collectorId,
      subjectKind: clip(o.subjectKind, 32),
      subjectKey: clip(o.subjectKey, 256),
      attribute: clip(o.attribute, 64),
      value: o.value ?? null,
      seenAt: new Date(o.seenAt || Date.now()),
    }));

    // Single batched INSERT instead of one per row — at ~200 obs/chunk
    // this is the difference between sub-millisecond and ~50ms per
    // chunk in our local benchmarks.
    await this.dataSource.transaction(async (em) => {
      await em.insert(Observation, rows);
      await em.increment(
        DiscoverySession,
        { id: chunk.sessionId },
        'observationCount',
        rows.length,
      );
    });

    // Mirror classified failures to the audit log. Cheap loop — most
    // observations are facts, not failures, so the filter passes through
    // quickly. This is chapter-2 exit-checklist item: "Auth-failure and
    // unreachable are distinguished in results and audit log."
    for (const obs of chunk.observations) {
      if (!FAILURE_ATTRIBUTES.has(obs.attribute)) continue;
      await this.audit
        .write({
          tenantId,
          actor: `collector:${collectorId}`,
          action: `device.${obs.attribute}`,
          entityKind: 'scan_job',
          entityId: session.scanJobId,
          metadata: {
            subjectKey: obs.subjectKey,
            value: obs.value,
          },
        })
        .catch((e) =>
          this.logger.warn(
            `audit write failed for ${obs.attribute}: ${e.message}`,
          ),
        );
    }
  }

  /**
   * Bootstrap a session row up-front so the collector's chunks have a
   * sessionId to reference before they start streaming. Called by the
   * dispatcher when it pushes ScanJobAssign.
   */
  async createSession(input: {
    tenantId: string;
    scanJobId: string;
    collectorId: string;
    pillar: string;
  }): Promise<DiscoverySession> {
    const session = this.sessions.create({
      tenantId: input.tenantId,
      scanJobId: input.scanJobId,
      collectorId: input.collectorId,
      pillar: input.pillar,
      endedAt: null,
      observationCount: 0,
    });
    return this.sessions.save(session);
  }
}

function clip(s: string, max: number): string {
  if (!s) return '';
  return s.length > max ? s.slice(0, max) : s;
}
