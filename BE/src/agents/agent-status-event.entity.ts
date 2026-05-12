import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';

/**
 * One row per online↔offline transition for an agent.
 *
 * Replaces per-tick `agent_heartbeats` rows. The WebSocket gateway calls
 * `markOnline` / `markOffline` on connect / disconnect; the service writes
 * a row here only when the agent's status actually changed. ~99% fewer
 * rows than per-tick heartbeats while still answering "how long was this
 * agent online today / this week."
 */
@Entity('agent_status_events')
@Index(['agentId', 'occurredAt'])
export class AgentStatusEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  @Index()
  agentId: string;

  @Column({ nullable: true })
  @Index()
  tenantId: string | null;

  @Column({ type: 'varchar', length: 16 })
  status: 'online' | 'offline';

  @Column({ type: 'timestamptz' })
  occurredAt: Date;

  @Column({ nullable: true })
  agentVersion: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
