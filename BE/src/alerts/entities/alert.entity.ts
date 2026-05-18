import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
} from 'typeorm';

/**
 * A stateful alert instance: one rule breach for one agent + scope.
 *
 * `dedupKey` = `${ruleId}:${agentId}:${scopeKey}` — the evaluator looks up
 * the firing alert by this key so a sustained breach UPDATES one row rather
 * than spawning duplicates. An alert lives `firing` → `resolved`.
 */
@Entity('alerts')
@Index(['tenantId', 'state'])
@Index(['dedupKey', 'state'])
@Index(['agentId', 'state'])
@Index(['incidentId'])
export class Alert {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', nullable: true })
  tenantId: string | null;

  @Column({ type: 'uuid' })
  ruleId: string;

  /** Denormalised rule name so the UI needn't join. */
  @Column()
  ruleName: string;

  @Column({ type: 'varchar' })
  metric: string;

  @Column({ type: 'varchar' })
  category: string;

  @Column()
  agentId: string;

  /** Scope within the agent — mountpoint / interface / gpu index. '' = host. */
  @Column({ default: '' })
  scopeKey: string;

  @Column()
  dedupKey: string;

  @Column({ type: 'varchar' })
  severity: 'warning' | 'critical';

  @Column({ type: 'varchar', default: 'firing' })
  state: 'firing' | 'resolved';

  @Column({ type: 'double precision', default: 0 })
  metricValue: number;

  @Column({ type: 'double precision', nullable: true })
  threshold: number | null;

  @Column({ type: 'text' })
  message: string;

  @Column({ type: 'timestamptz' })
  firstFiredAt: Date;

  @Column({ type: 'timestamptz' })
  lastEvaluatedAt: Date;

  @Column({ type: 'timestamptz', nullable: true })
  resolvedAt: Date | null;

  @Column({ type: 'uuid', nullable: true })
  incidentId: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
