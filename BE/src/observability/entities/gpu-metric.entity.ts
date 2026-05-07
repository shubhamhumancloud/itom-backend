import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

const bigint = {
  transformer: {
    to: (v: number | null) => v,
    from: (v: string | null) => (v != null ? parseInt(v, 10) : null),
  },
};

@Entity('gpu_metrics')
@Index(['agentId', 'timestamp'])
@Index(['agentId', 'gpuIndex', 'timestamp'])
export class GpuMetric {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column()
  agentId: string;

  @Column({ type: 'timestamptz' })
  timestamp: Date;

  @Column({ type: 'int' })
  gpuIndex: number;

  @Column()
  name: string;

  @Column({ type: 'numeric', precision: 5, scale: 2 })
  utilizationPercent: number;

  @Column({ type: 'bigint', default: 0, ...bigint })
  memoryUsedBytes: number;

  @Column({ type: 'bigint', default: 0, ...bigint })
  memoryTotalBytes: number;

  @Column({ type: 'numeric', precision: 5, scale: 1, nullable: true })
  temperatureC: number | null;

  @Column({ type: 'numeric', precision: 6, scale: 1, nullable: true })
  powerWatts: number | null;
}
