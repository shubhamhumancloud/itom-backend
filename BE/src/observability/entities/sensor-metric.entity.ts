import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

@Entity('sensor_metrics')
@Index(['agentId', 'timestamp'])
@Index(['agentId', 'name', 'timestamp'])
export class SensorMetric {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column()
  agentId: string;

  @Column({ type: 'timestamptz' })
  timestamp: Date;

  @Column()
  name: string;

  @Column({ type: 'varchar', length: 32 })
  kind: 'temperature_c' | 'fan_rpm';

  @Column({ type: 'numeric', precision: 8, scale: 2 })
  value: number;
}
