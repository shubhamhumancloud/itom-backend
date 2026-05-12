import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * One (device, interface, IP) binding. A device may have many IPs
 * across interfaces; we de-dup by the (interfaceId, ip) pair.
 */
@Entity({ name: 'disc_ip_binding' })
@Index(['interfaceId', 'ip'], { unique: true })
@Index(['tenantId', 'deviceId'])
@Index(['tenantId', 'ip'])
export class IpBinding {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'uuid' })
  deviceId!: string;

  @Column({ type: 'uuid' })
  interfaceId!: string;

  @Column({ type: 'inet' })
  ip!: string;

  @Column({ type: 'integer', nullable: true })
  prefixLen!: number | null;

  @Column({ type: 'timestamptz', nullable: true })
  lastSeenAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
