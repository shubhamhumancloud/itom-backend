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

@Entity('network_metrics')
@Index(['agentId', 'interfaceName', 'timestamp'])
export class NetworkMetric {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  @Index()
  agentId: string;

  @Column()
  interfaceName: string;

  @Column({ type: 'timestamptz' })
  timestamp: Date;

  @Column({ type: 'bigint', ...bigint })
  bytesSent: number;

  @Column({ type: 'bigint', ...bigint })
  bytesRecv: number;

  @Column({ type: 'bigint', ...bigint })
  packetsSent: number;

  @Column({ type: 'bigint', ...bigint })
  packetsRecv: number;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
