import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * One interface on one device. The (deviceId, ifIndex) tuple is the
 * stable identity — ifIndex is the SNMP IF-MIB index (an int) or, for
 * firewall ingest, a synthetic monotonically-assigned number per port
 * name.
 */
@Entity({ name: 'disc_interface' })
@Index(['deviceId', 'ifIndex'], { unique: true })
@Index(['tenantId', 'deviceId'])
export class NetworkInterface {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'uuid' })
  deviceId!: string;

  @Column({ type: 'integer' })
  ifIndex!: number;

  @Column({ type: 'varchar', length: 128 })
  name!: string;

  @Column({ type: 'varchar', length: 256, nullable: true })
  description!: string | null;

  @Column({ type: 'varchar', length: 32, nullable: true })
  type!: string | null; // ethernet, vlan, tunnel, loopback, …

  @Column({ type: 'bigint', default: 0 })
  speedBps!: string; // stored as bigint; bigint round-trips as string in pg

  @Column({ type: 'varchar', length: 17, nullable: true })
  mac!: string | null;

  @Column({ type: 'varchar', length: 16, default: 'unknown' })
  adminStatus!: string;

  @Column({ type: 'varchar', length: 16, default: 'unknown' })
  operStatus!: string;

  @Column({ type: 'varchar', length: 64, nullable: true })
  zone!: string | null;

  @Column({ type: 'timestamptz', nullable: true })
  lastSeenAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
