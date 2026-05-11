import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

export type ScanJobPillar = 'noop' | 'firewall' | 'snmp' | 'active';
export type ScanJobStatus =
  | 'queued'
  | 'assigned'
  | 'running'
  | 'completed'
  | 'failed'
  | 'timeout'
  | 'refused';

/**
 * A single scan instruction. The dashboard inserts a row, NOTIFYs the
 * collector channel, and the collector picks it up via WS. Result observations
 * are written under resultSessionId.
 */
@Entity({ name: 'disc_scan_job' })
@Index(['tenantId', 'status'])
@Index(['collectorId', 'status'])
export class ScanJob {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  /** Which collector this job is targeted at. NULL = any collector for tenant. */
  @Column({ type: 'uuid', nullable: true })
  collectorId!: string | null;

  @Column({ type: 'varchar', length: 32 })
  pillar!: ScanJobPillar;

  /** Free-form per-pillar parameters: CIDRs, seed device IPs, etc. */
  @Column({ type: 'jsonb', default: () => `'{}'` })
  targetSpec!: Record<string, unknown>;

  /** Credential IDs the collector should request JIT before running. */
  @Column({ type: 'jsonb', default: () => `'[]'` })
  credentialRefs!: string[];

  @Column({ type: 'varchar', length: 16, default: 'queued' })
  status!: ScanJobStatus;

  @Column({ type: 'text', nullable: true })
  statusReason!: string | null;

  @Column({ type: 'uuid', nullable: true })
  resultSessionId!: string | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
