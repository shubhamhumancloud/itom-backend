import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';

const bigint = {
  transformer: {
    to: (v: number) => v,
    from: (v: string) => (v != null ? parseInt(v, 10) : null),
  },
};

@Entity('agents')
export class Agent {
  @PrimaryColumn()
  agentId: string;

  @Column({ nullable: true })
  @Index()
  tenantId: string | null;

  @Column({ nullable: true })
  agentVersion: string;

  @Column({ nullable: true })
  @Index()
  fingerprintHash: string;

  @Column({ nullable: true })
  hostname: string;

  @Column({ nullable: true })
  os: string;

  @Column({ nullable: true })
  arch: string;

  @Column({ nullable: true })
  platform: string;

  @Column({ nullable: true })
  platformVersion: string;

  @Column({ nullable: true })
  kernelVersion: string;

  @Column({ type: 'text', array: true, nullable: true })
  ethernetIPs: string[];

  @Column({ type: 'text', array: true, nullable: true })
  wifiIPs: string[];

  @Column({ type: 'text', array: true, nullable: true })
  macAddresses: string[];

  @Column({ nullable: true })
  cpuModel: string;

  @Column({ type: 'int', nullable: true })
  cpuCores: number;

  @Column({ type: 'bigint', nullable: true, ...bigint })
  totalMemoryBytes: number;

  @Column({ type: 'bigint', nullable: true, ...bigint })
  totalDiskBytes: number;

  @CreateDateColumn({ type: 'timestamptz' })
  registeredAt: Date;

  @Column({ type: 'timestamptz', nullable: true })
  lastSeenAt: Date | null;

  @Column({ default: 'unknown' })
  status: string;

  @Column({ type: 'timestamptz', nullable: true })
  statusChangedAt: Date | null;
}
