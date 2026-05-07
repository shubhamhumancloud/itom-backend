import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

const bigint = {
  transformer: {
    to: (v: number | null) => v,
    from: (v: string | null) => (v != null ? parseInt(v, 10) : null),
  },
};

@Entity('process_metrics')
@Index(['agentId', 'timestamp'])
@Index(['agentId', 'processName', 'timestamp'])
export class ProcessMetric {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column()
  agentId: string;

  @Column({ type: 'timestamptz' })
  timestamp: Date;

  @Column()
  processName: string;

  @Column({ type: 'int', default: 1 })
  pidCount: number;

  @Column({ type: 'numeric', precision: 6, scale: 2, default: 0 })
  cpuPercent: number;

  @Column({ type: 'bigint', default: 0, ...bigint })
  memoryBytes: number;

  @Column({ type: 'bigint', nullable: true, ...bigint })
  ioReadBytes: number | null;

  @Column({ type: 'bigint', nullable: true, ...bigint })
  ioWriteBytes: number | null;
}
