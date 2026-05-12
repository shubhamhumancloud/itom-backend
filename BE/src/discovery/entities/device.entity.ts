import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * One logical device — produced by fusion. Identity is keyed by
 * chassis serial when available, otherwise by an aggregated MAC,
 * otherwise by management IP. The identity key (`identityKey`) is
 * what fusion looks up to merge new observations into an existing
 * row vs. create a new one.
 *
 * State axes per chapter 4 doc:
 *   - lifecycleState: "does this device still exist?"
 *   - availabilityState: "is it on right now?"
 * They're independent so a decommissioned device that briefly
 * reappears (someone plugged it back in) flips availability without
 * flipping lifecycle.
 */
export type DeviceLifecycleState = 'active' | 'decommissioned' | 'archived';
export type DeviceAvailabilityState = 'up' | 'down' | 'unknown' | 'maintenance';
export type DeviceKind =
  | 'firewall'
  | 'router'
  | 'switch'
  | 'server'
  | 'workstation'
  | 'printer'
  | 'camera'
  | 'iot'
  | 'unknown';

@Entity({ name: 'disc_device' })
@Index(['tenantId', 'identityKey'], { unique: true })
@Index(['tenantId', 'siteId'])
@Index(['tenantId', 'lastSeenAt'])
export class Device {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'uuid', nullable: true })
  siteId!: string | null;

  /**
   * Stable identity for dedup. Format:
   *   "chassis:<serial>"   when a serial is known (preferred)
   *   "mac:<aa:bb:..>"     when no serial but a chassis-MAC is known
   *   "ip:<10.0.0.1>"      last resort
   *
   * Two observations producing the same identityKey converge to the
   * same Device row.
   */
  @Column({ type: 'varchar', length: 128 })
  identityKey!: string;

  @Column({ type: 'varchar', length: 256, nullable: true })
  hostname!: string | null;

  @Column({ type: 'varchar', length: 32 })
  kind!: DeviceKind;

  @Column({ type: 'varchar', length: 64, nullable: true })
  vendor!: string | null;

  @Column({ type: 'varchar', length: 128, nullable: true })
  model!: string | null;

  @Column({ type: 'varchar', length: 64, nullable: true })
  chassisSerial!: string | null;

  @Column({ type: 'varchar', length: 256, nullable: true })
  sysDescr!: string | null;

  @Column({ type: 'inet', nullable: true })
  managementIp!: string | null;

  @Column({ type: 'varchar', length: 16, default: 'active' })
  lifecycleState!: DeviceLifecycleState;

  @Column({ type: 'varchar', length: 16, default: 'unknown' })
  availabilityState!: DeviceAvailabilityState;

  @Column({ type: 'timestamptz', nullable: true })
  lastSeenAt!: Date | null;

  /**
   * The list of pillars that have ever produced a fact about this
   * device — useful provenance in the side panel ("seen by SNMP +
   * active scanner").
   */
  @Column({ type: 'jsonb', default: () => `'[]'` })
  sources!: string[];

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
