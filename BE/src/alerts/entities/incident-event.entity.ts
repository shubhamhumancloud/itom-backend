import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

/**
 * Append-only audit timeline for an incident: every state change and every
 * alert that joined or recovered, plus human comments.
 */
@Entity('incident_events')
@Index(['incidentId', 'occurredAt'])
export class IncidentEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  incidentId: string;

  /** opened | alert_added | alert_resolved | severity_changed | acknowledged | resolved | comment */
  @Column({ type: 'varchar' })
  type: string;

  @Column({ type: 'text' })
  message: string;

  /** 'system' for evaluator-generated events, else the tenant user. */
  @Column({ type: 'varchar', nullable: true })
  actor: string | null;

  @Column({ type: 'timestamptz' })
  occurredAt: Date;
}
