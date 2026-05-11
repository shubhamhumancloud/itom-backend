import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
} from 'typeorm';

/**
 * Append-only diary of who did what in the discovery module. Inserts only;
 * never updated. Pruning is a future concern (move > N days to cold storage).
 */
@Entity({ name: 'disc_audit_log' })
@Index(['tenantId', 'createdAt'])
@Index(['tenantId', 'action'])
export class AuditLog {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  /** User id, system process name, or "collector:<id>". */
  @Column({ type: 'varchar', length: 128 })
  actor!: string;

  /** e.g. "scan.created", "credential.decrypted", "cidr.refused". */
  @Column({ type: 'varchar', length: 64 })
  action!: string;

  @Column({ type: 'varchar', length: 64, nullable: true })
  entityKind!: string | null;

  @Column({ type: 'uuid', nullable: true })
  entityId!: string | null;

  @Column({ type: 'jsonb', default: () => `'{}'` })
  metadata!: Record<string, unknown>;

  @CreateDateColumn()
  createdAt!: Date;
}
