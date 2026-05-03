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

@Entity('metrics')
@Index(['agentId', 'timestamp'])
export class Metric {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  @Index()
  agentId: string;

  @Column({ type: 'timestamptz' })
  timestamp: Date;

  @Column({ type: 'double precision' })
  cpuPercent: number;

  @Column({ type: 'double precision' })
  memoryPercent: number;

  @Column({ type: 'double precision' })
  diskPercent: number;

  @Column({ type: 'bigint', nullable: true, ...bigint })
  memAvailableBytes: number | null;

  @Column({ type: 'double precision', nullable: true })
  loadAvg1m: number | null;

  @Column({ type: 'int', nullable: true })
  processCount: number | null;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
