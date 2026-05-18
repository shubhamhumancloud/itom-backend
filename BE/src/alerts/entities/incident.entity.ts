import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Human-facing record. One open incident per (agentId, category) — a disk
 * problem and a CPU problem on the same host are separate incidents. Every
 * alert for that host+category attaches to it. Closes MANUALLY only — even
 * after all alerts recover, a person must resolve it.
 */
@Entity('incidents')
@Index(['tenantId', 'status'])
@Index(['agentId', 'category', 'status'])
export class Incident {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', nullable: true })
  tenantId: string | null;

  @Column()
  agentId: string;

  @Column({ type: 'varchar' })
  category: string;

  @Column()
  title: string;

  @Column({ type: 'varchar', default: 'warning' })
  severity: 'warning' | 'critical';

  @Column({ type: 'varchar', default: 'open' })
  status: 'open' | 'acknowledged' | 'resolved';

  /** Total alerts ever attached (firing + resolved). */
  @Column({ type: 'int', default: 0 })
  alertCount: number;

  @Column({ type: 'timestamptz' })
  openedAt: Date;

  @Column({ type: 'timestamptz', nullable: true })
  acknowledgedAt: Date | null;

  @Column({ type: 'varchar', nullable: true })
  acknowledgedBy: string | null;

  @Column({ type: 'timestamptz', nullable: true })
  resolvedAt: Date | null;

  @Column({ type: 'varchar', nullable: true })
  resolvedBy: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updatedAt: Date;
}
