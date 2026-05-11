import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * A registered discovery collector — the Go `itom-collector` daemon
 * running inside a customer's network. One row per binary install.
 *
 * Identity model:
 *   - `id` is the canonical UUID we expose to operators.
 *   - `authToken` (sha256 of a 32-byte random string) is what the
 *     collector presents on the WS handshake and on credential-decrypt
 *     calls. Stored hashed, never in plaintext.
 *   - `allowedCidrs` is the per-tenant CIDR scope this collector is
 *     allowed to scan. The list is signed by the BE on every
 *     `scan_job.assign` so the collector cannot be tricked into
 *     scanning outside it.
 */
@Entity({ name: 'disc_collector' })
@Index(['tenantId', 'name'], { unique: true })
export class Collector {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  /** Human label used in the dashboard. "HQ Mumbai collector". */
  @Column({ type: 'varchar', length: 128 })
  name!: string;

  /** SHA-256 hex of the bearer the collector presents. 64 chars. */
  @Column({ type: 'varchar', length: 64 })
  authTokenHash!: string;

  /** CIDRs this collector is permitted to scan, signed on every assign. */
  @Column({ type: 'jsonb', default: () => `'[]'` })
  allowedCidrs!: string[];

  @Column({ type: 'varchar', length: 16, default: 'offline' })
  status!: 'online' | 'offline' | 'disabled';

  @Column({ type: 'timestamptz', nullable: true })
  lastSeenAt!: Date | null;

  @Column({ type: 'varchar', length: 64, nullable: true })
  version!: string | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
