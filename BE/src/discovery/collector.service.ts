import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as crypto from 'crypto';
import { Collector } from './entities/collector.entity';

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
}

function sha256Hex(s: string): string {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}
