import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * A physical or logical location within a tenant. For chapter 4 MVP
 * every tenant has one default site ("Primary") into which all
 * discovered devices land. Multi-site discrimination is a chapter
 * 5+ concern once the operator UI gains site-tagging.
 */
@Entity({ name: 'disc_site' })
@Index(['tenantId', 'name'], { unique: true })
export class Site {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'varchar', length: 128 })
  name!: string;

  @Column({ type: 'text', nullable: true })
  description!: string | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
