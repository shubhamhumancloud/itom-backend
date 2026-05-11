import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
} from 'typeorm';

/**
 * The unit of truth. Every fact produced by any pillar (firewall ingest,
 * SNMP crawl, active scan) lands here first; fusion (Chapter 4) turns
 * observations into current-state device / interface / edge rows.
 *
 * subjectKind/subjectKey describes WHAT the fact is about:
 *   subjectKind = "device", subjectKey = "ip:10.0.5.42"
 *   subjectKind = "route",  subjectKey = "vr:default|prefix:10.20.0.0/16"
 *
 * attribute/valueJson is the fact itself. Free-form jsonb so we never need
 * a migration when a new pillar wants to record a new kind of fact.
 */
@Entity({ name: 'disc_observation' })
@Index(['tenantId', 'sessionId'])
@Index(['tenantId', 'subjectKind', 'subjectKey'])
@Index(['tenantId', 'seenAt'])
export class Observation {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'uuid' })
  sessionId!: string;

  @Column({ type: 'uuid' })
  collectorId!: string;

  @Column({ type: 'varchar', length: 32 })
  subjectKind!: string;

  @Column({ type: 'varchar', length: 256 })
  subjectKey!: string;

  @Column({ type: 'varchar', length: 64 })
  attribute!: string;

  @Column({ type: 'jsonb' })
  value!: unknown;

  @Column({ type: 'timestamptz' })
  seenAt!: Date;

  @CreateDateColumn()
  createdAt!: Date;
}
