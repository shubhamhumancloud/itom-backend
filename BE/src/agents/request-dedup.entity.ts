import { Entity, PrimaryColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('request_dedup')
export class RequestDedup {
  @PrimaryColumn()
  requestId: string;

  @Column()
  agentId: string;

  @Column()
  endpoint: string;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
