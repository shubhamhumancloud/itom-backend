import { Column, Entity, Index, PrimaryColumn, UpdateDateColumn } from 'typeorm';

const bigint = {
  transformer: {
    to: (v: number | null) => v,
    from: (v: string | null) => (v != null ? parseInt(v, 10) : null),
  },
};

/**
 * Current installed-software state per agent. Not time series.
 * Upserted by (agentId, name, version). lastSeenAt updates each daily snapshot.
 * Apps no longer present after a snapshot are detectable by lastSeenAt < cutoff.
 */
@Entity('software_inventory')
@Index(['agentId', 'name'])
export class SoftwareItem {
  @PrimaryColumn()
  agentId: string;

  @PrimaryColumn()
  name: string;

  @PrimaryColumn()
  version: string;

  @Column({ nullable: true })
  publisher: string | null;

  @Column({ type: 'date', nullable: true })
  installedAt: string | null;

  @Column({ type: 'bigint', nullable: true, ...bigint })
  sizeBytes: number | null;

  @Column({ type: 'varchar', length: 16 })
  source: string;

  @Column({ type: 'timestamptz' })
  firstSeenAt: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  lastSeenAt: Date;
}
