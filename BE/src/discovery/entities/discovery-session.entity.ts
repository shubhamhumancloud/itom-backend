import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
} from 'typeorm';

/**
 * One execution of a scan job. Groups all observations produced in that run
 * so we can attribute findings to a specific collector + time window.
 */
@Entity({ name: 'disc_discovery_session' })
@Index(['tenantId', 'startedAt'])
export class DiscoverySession {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'uuid' })
  scanJobId!: string;

  @Column({ type: 'uuid' })
  collectorId!: string;

  @Column({ type: 'varchar', length: 32 })
  pillar!: string;

  @CreateDateColumn()
  startedAt!: Date;

  @Column({ type: 'timestamptz', nullable: true })
  endedAt!: Date | null;

  @Column({ type: 'integer', default: 0 })
  observationCount!: number;
}
