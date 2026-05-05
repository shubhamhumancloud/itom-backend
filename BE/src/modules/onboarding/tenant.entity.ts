import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('itom_tenants')
export class Tenant {
  @PrimaryColumn()
  tenantId: string;

  @Column({ nullable: true })
  orgId: string;

  @Column({ nullable: true })
  name: string;

  @Column({ nullable: true })
  plan: string;

  @Column({ default: 'active' })
  status: 'active' | 'suspended' | 'pending' | string;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updatedAt: Date;
}
