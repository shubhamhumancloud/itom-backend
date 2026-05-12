import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * One open service port discovered by the active scanner. (deviceId,
 * port, protocol) is the unique key; banner+service+tls cert fields
 * accumulate the most recent fact.
 */
@Entity({ name: 'disc_open_port' })
@Index(['tenantId', 'deviceId'])
@Index(['deviceId', 'port', 'protocol'], { unique: true })
export class OpenPort {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'uuid' })
  deviceId!: string;

  @Column({ type: 'integer' })
  port!: number;

  @Column({ type: 'varchar', length: 8, default: 'tcp' })
  protocol!: string;

  @Column({ type: 'varchar', length: 32, nullable: true })
  service!: string | null;

  @Column({ type: 'text', nullable: true })
  banner!: string | null;

  @Column({ type: 'varchar', length: 256, nullable: true })
  tlsCertCn!: string | null;

  @Column({ type: 'jsonb', default: () => `'[]'` })
  tlsCertSans!: string[];

  @Column({ type: 'timestamptz', nullable: true })
  lastSeenAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
