import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';

const bigint = {
  transformer: {
    to: (v: number | null | undefined) => v ?? null,
    from: (v: string | null) =>
      v != null ? parseInt(v, 10) : null,
  },
};

@Entity('agent_heartbeats')
@Index(['agentId', 'timestamp'])
export class AgentHeartbeat {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  @Index()
  agentId: string;

  @Column({ type: 'timestamptz' })
  timestamp: Date;

  @Column({ nullable: true })
  agentVersion: string | null;

  @Column({ type: 'bigint', nullable: true, ...bigint })
  uptimeSeconds: number | null;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
