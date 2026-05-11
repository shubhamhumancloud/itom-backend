import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from './entities/audit-log.entity';

/**
 * Tiny write-only logger. Reads can wait — when we need them we'll build a
 * paginated controller endpoint.
 */
@Injectable()
export class AuditLogService {
  constructor(
    @InjectRepository(AuditLog)
    private readonly repo: Repository<AuditLog>,
  ) {}

  async write(input: {
    tenantId: string;
    actor: string;
    action: string;
    entityKind?: string | null;
    entityId?: string | null;
    metadata?: Record<string, unknown>;
  }): Promise<void> {
    await this.repo.insert({
      tenantId: input.tenantId,
      actor: input.actor,
      action: input.action,
      entityKind: input.entityKind ?? null,
      entityId: input.entityId ?? null,
      metadata: input.metadata ?? {},
    });
  }
}
