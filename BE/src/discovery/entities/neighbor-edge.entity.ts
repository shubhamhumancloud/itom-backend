import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

export type EdgeKind = 'lldp' | 'cdp' | 'l3_adjacency' | 'ipsec_tunnel' | 'arp';

/**
 * A topology edge between two devices. The (fromDeviceId, toDeviceId,
 * kind) tuple isn't strictly unique — two parallel cables between
 * switches produce two LLDP edges on different ports. So we
 * additionally dedup by (fromIfIndex, toIfIndex) when known.
 *
 * "neighbor_edge" naming mirrors the chapter doc.
 */
@Entity({ name: 'disc_neighbor_edge' })
@Index(['tenantId', 'fromDeviceId'])
@Index(['tenantId', 'toDeviceId'])
@Index(['tenantId', 'fromDeviceId', 'toDeviceId', 'kind', 'fromIfIndex', 'toIfIndex'], {
  unique: true,
})
export class NeighborEdge {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'uuid' })
  fromDeviceId!: string;

  @Column({ type: 'uuid' })
  toDeviceId!: string;

  @Column({ type: 'varchar', length: 16 })
  kind!: EdgeKind;

  @Column({ type: 'integer', nullable: true })
  fromIfIndex!: number | null;

  @Column({ type: 'integer', nullable: true })
  toIfIndex!: number | null;

  /** Free-form: peer port name when it's known but ifIndex isn't. */
  @Column({ type: 'jsonb', default: () => `'{}'` })
  meta!: Record<string, unknown>;

  @Column({ type: 'timestamptz', nullable: true })
  lastSeenAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
