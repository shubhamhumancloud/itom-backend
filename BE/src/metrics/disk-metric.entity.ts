import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';

const bigint = {
  transformer: {
    to: (v: number) => v,
    from: (v: string) => (v != null ? parseInt(v, 10) : null),
  },
};

@Entity('disk_metrics')
@Index(['agentId', 'mountpoint', 'timestamp'])
export class DiskMetric {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  @Index()
  agentId: string;

  @Column()
  mountpoint: string;

  @Column({ type: 'timestamptz' })
  timestamp: Date;

  @Column({ type: 'double precision' })
  usedPercent: number;

  @Column({ type: 'bigint', ...bigint })
  usedBytes: number;

  @Column({ type: 'bigint', ...bigint })
  totalBytes: number;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
