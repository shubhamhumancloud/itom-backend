import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Metric a rule watches.
 *  - host-scoped:   cpu, memory, battery
 *  - scoped:        disk (mountpoint), gpu_temp (gpu), cpu_temp (sensor),
 *                   process_cpu (process), net_throughput (interface)
 *  - availability:  agent_offline, agent_flapping (event-driven, no window)
 */
export type AlertMetric =
  | 'cpu'
  | 'memory'
  | 'disk'
  | 'gpu_temp'
  | 'cpu_temp'
  | 'battery'
  | 'process_cpu'
  | 'net_throughput'
  | 'agent_offline'
  | 'agent_flapping';

/** Incident category an alert from this rule rolls up into. */
export type AlertCategory =
  | 'compute'
  | 'storage'
  | 'thermal'
  | 'power'
  | 'network'
  | 'availability'
  | 'process';

/**
 * A tenant-scoped (or global, when tenantId is null) threshold definition.
 * The evaluator turns a sustained breach of these thresholds into an Alert.
 */
@Entity('alert_rules')
@Index(['tenantId', 'enabled'])
export class AlertRule {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** null = global default rule applied to every tenant. */
  @Column({ type: 'varchar', nullable: true })
  tenantId: string | null;

  /**
   * Stable slug for built-in rules (e.g. `builtin-cpu`); null for
   * user-created / tenant-override rules. Lets seeding be idempotent and
   * upgrade-safe across releases.
   */
  @Column({ type: 'varchar', nullable: true })
  @Index()
  key: string | null;

  @Column()
  name: string;

  @Column({ type: 'varchar' })
  metric: AlertMetric;

  @Column({ type: 'varchar' })
  category: AlertCategory;

  /**
   * Comparison direction:
   *  - `gte` — breach when value ≥ threshold (CPU, disk, temperature, …)
   *  - `lt`  — breach when value ≤ threshold (battery — low is bad)
   */
  @Column({ type: 'varchar', default: 'gte' })
  comparator: string;

  @Column({ type: 'double precision', nullable: true })
  warningThreshold: number | null;

  @Column({ type: 'double precision', nullable: true })
  criticalThreshold: number | null;

  /** Hysteresis: a firing alert only resolves once value drops below this. */
  @Column({ type: 'double precision', nullable: true })
  recoveryThreshold: number | null;

  /** The breach must persist this long before the alert fires. */
  @Column({ type: 'int', default: 300 })
  forSeconds: number;

  @Column({ default: true })
  enabled: boolean;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updatedAt: Date;
}
