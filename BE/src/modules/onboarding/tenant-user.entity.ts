import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';

@Entity('itom_tenant_users')
@Index(['tenantId', 'userId'], { unique: true })
export class TenantUser {
  @PrimaryColumn()
  userId: string;

  @PrimaryColumn()
  tenantId: string;

  @Column({ nullable: true })
  email: string;

  @Column({ nullable: true })
  fullName: string;

  @Column({ type: 'text', array: true, nullable: true })
  roles: string[];

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
