import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

@Entity('battery_metrics')
@Index(['agentId', 'timestamp'])
export class BatteryMetric {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column()
  agentId: string;

  @Column({ type: 'timestamptz' })
  timestamp: Date;

  @Column({ type: 'numeric', precision: 5, scale: 2 })
  percent: number;

  @Column({ default: false })
  charging: boolean;

  @Column({ default: false })
  onAC: boolean;

  @Column({ type: 'int', nullable: true })
  cycleCount: number | null;

  @Column({ type: 'int', nullable: true })
  designCapacityMwh: number | null;

  @Column({ type: 'int', nullable: true })
  fullCapacityMwh: number | null;

  @Column({ type: 'numeric', precision: 5, scale: 2, nullable: true })
  healthPercent: number | null;

  @Column({ type: 'int', nullable: true })
  timeToFullSeconds: number | null;

  @Column({ type: 'int', nullable: true })
  timeToEmptySeconds: number | null;
}
