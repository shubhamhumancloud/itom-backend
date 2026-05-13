import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, In, Repository } from 'typeorm';
import * as crypto from 'crypto';
import { Collector } from './entities/collector.entity';
import { ScanJob } from './entities/scan-job.entity';
import { DiscoverySession } from './entities/discovery-session.entity';
import { Observation } from './entities/observation.entity';

/**
 * Collector CRUD + auth-token verification. The dashboard creates a
 * Collector row via POST /v1/discovery/collectors; the response carries
 * the one-time plaintext bearer (we keep only the SHA-256 hash). The
 * operator pastes that bearer into the collector's install script /
 * env var.
 */
@Injectable()
export class CollectorService {
  constructor(
    @InjectRepository(Collector)
    private readonly repo: Repository<Collector>,
    @InjectRepository(ScanJob)
    private readonly jobs: Repository<ScanJob>,
    @InjectRepository(DiscoverySession)
    private readonly sessions: Repository<DiscoverySession>,
    @InjectRepository(Observation)
    private readonly observations: Repository<Observation>,
    @InjectDataSource()
    private readonly dataSource: DataSource,
  ) {}

  async create(input: {
    tenantId: string;
    name: string;
    allowedCidrs?: string[];
  }): Promise<{ collector: Collector; plaintextToken: string }> {
    const plaintextToken = crypto.randomBytes(32).toString('hex'); // 64 chars
    const hash = sha256Hex(plaintextToken);
    const saved = await this.repo.save(
      this.repo.create({
        tenantId: input.tenantId,
        name: input.name,
        authTokenHash: hash,
        allowedCidrs: input.allowedCidrs ?? [],
        status: 'offline',
      }),
    );
    return { collector: saved, plaintextToken };
  }

  async list(tenantId: string): Promise<Collector[]> {
    return this.repo.find({
      where: { tenantId },
      order: { createdAt: 'DESC' },
    });
  }

  async getOne(tenantId: string, id: string): Promise<Collector> {
    const row = await this.repo.findOneBy({ id, tenantId });
    if (!row) throw new NotFoundException('collector not found');
    return row;
  }

  /**
   * Verify a collector-presented bearer. Returns the canonical row or
   * throws Unauthorized. We look the row up by id first, then compare
   * the hash, so a token leaked for collector A can't be replayed as
   * collector B.
   */
  async verifyToken(collectorId: string, presented: string): Promise<Collector> {
    const row = await this.repo.findOneBy({ id: collectorId });
    if (!row) throw new UnauthorizedException('unknown collector');
    const presentedHash = sha256Hex(presented);
    if (!constantTimeEqual(presentedHash, row.authTokenHash)) {
      throw new UnauthorizedException('bad collector token');
    }
    if (row.status === 'disabled') {
      throw new UnauthorizedException('collector disabled');
    }
    return row;
  }

  async markOnline(id: string, version: string | null): Promise<void> {
    await this.repo.update(
      { id },
      { status: 'online', lastSeenAt: new Date(), version: version ?? null },
    );
  }

  async markOffline(id: string): Promise<void> {
    await this.repo.update({ id }, { status: 'offline' });
  }

  async setAllowedCidrs(tenantId: string, id: string, cidrs: string[]): Promise<Collector> {
    const row = await this.getOne(tenantId, id);
    row.allowedCidrs = cidrs;
    return this.repo.save(row);
  }

  /**
   * Delete a collector and every observation / session / scan-job it
   * produced. We refuse to delete an `online` collector — bring it
   * down first (operators have to know the daemon was stopped). Typed
   * device / interface / edge / open-port rows are LEFT IN PLACE: a
   * device can be fused from observations across multiple collectors,
   * and deleting it here would corrupt the typed graph.
   *
   * If the operator wants to wipe the topology too, they should use
   * the demo-clear endpoint (which is scoped to demo-seed jobs) or
   * delete the device rows directly.
   */
  async delete(tenantId: string, id: string): Promise<{
    scanJobs: number;
    sessions: number;
    observations: number;
  }> {
    const row = await this.getOne(tenantId, id);
    if (row.status === 'online') {
      throw new BadRequestException(
        'cannot delete an online collector — stop the daemon (or wait for it to time out) first',
      );
    }

    // 1) Find every scan-job the collector produced.
    const jobs = await this.jobs.find({
      where: { tenantId, collectorId: id },
      select: ['id'],
    });
    const jobIds = jobs.map((j) => j.id);

    // 2) Find every session those jobs produced (plus any direct sessions
    //    on the collector — early bootstrap path emitted some).
    const sessionsByJob = jobIds.length
      ? await this.sessions.find({ where: { scanJobId: In(jobIds) }, select: ['id'] })
      : [];
    const sessionsByCol = await this.sessions.find({
      where: { tenantId, collectorId: id },
      select: ['id'],
    });
    const sessionIds = Array.from(
      new Set([...sessionsByJob.map((s) => s.id), ...sessionsByCol.map((s) => s.id)]),
    );

    // 3) Cascade-delete observations → sessions → jobs → collector.
    let obsDeleted = 0;
    if (sessionIds.length > 0) {
      const r = await this.observations.delete({ sessionId: In(sessionIds) });
      obsDeleted = r.affected ?? 0;
      await this.sessions.delete({ id: In(sessionIds) });
    }
    if (jobIds.length > 0) {
      await this.jobs.delete({ id: In(jobIds) });
    }
    await this.repo.delete({ id, tenantId });

    return {
      scanJobs: jobIds.length,
      sessions: sessionIds.length,
      observations: obsDeleted,
    };
  }
}

function sha256Hex(s: string): string {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}
