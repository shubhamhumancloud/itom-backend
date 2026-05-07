import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

@Entity('disk_health')
@Index(['agentId', 'device', 'timestamp'])
export class DiskHealth {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column()
  agentId: string;

  @Column({ type: 'timestamptz' })
  timestamp: Date;

  @Column()
  device: string;

  @Column({ nullable: true })
  model: string | null;

  @Column({ type: 'varchar', length: 16 })
  status: 'healthy' | 'warning' | 'failing' | 'unknown';

  @Column({ default: false })
  predictedFailure: boolean;

  @Column({ type: 'numeric', precision: 5, scale: 1, nullable: true })
  temperatureC: number | null;

  @Column({ type: 'int', nullable: true })
  powerOnHours: number | null;

  @Column({ type: 'int', nullable: true })
  reallocatedSectors: number | null;

  @Column({ type: 'numeric', precision: 5, scale: 1, nullable: true })
  wearLevelingPercent: number | null;
}
