import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
} from 'typeorm';

export type DiscoveryEventKind =
  | 'device_added'
  | 'device_disappeared'
  | 'device_moved_port'
  | 'new_open_port'
  | 'new_neighbor_edge'
  | 'attribute_changed';

/**
 * Append-only feed of interesting changes. Surfaced on the dashboard;
 * chapter 5 turns them into alerts. Single-table for all kinds —
 * keeps queries simple ("recent events for tenant X").
 */
@Entity({ name: 'disc_discovery_event' })
@Index(['tenantId', 'createdAt'])
@Index(['tenantId', 'kind'])
@Index(['tenantId', 'deviceId'])
export class DiscoveryEvent {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'uuid', nullable: true })
  deviceId!: string | null;

  @Column({ type: 'varchar', length: 32 })
  kind!: DiscoveryEventKind;

  @Column({ type: 'jsonb', default: () => `'{}'` })
  payload!: Record<string, unknown>;

  @CreateDateColumn()
  createdAt!: Date;
}
