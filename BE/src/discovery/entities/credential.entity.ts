import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
} from 'typeorm';

export type CredentialKind =
  | 'snmp_v2c'
  | 'snmp_v3'
  | 'ssh_password'
  | 'ssh_key'
  | 'firewall_api_key';

/**
 * Encrypted secret used by a collector to authenticate against customer
 * gear (firewalls, switches, routers). Envelope-encrypted:
 *   - wrappedDek = AES-256-GCM(masterKey, dek)
 *   - ciphertext = AES-256-GCM(dek,       plaintext)
 *
 * Plaintext only ever exists in the BE during encrypt/decrypt and in the
 * collector's RAM during a single scan job. Never on disk anywhere.
 */
@Entity({ name: 'disc_credential' })
@Index(['tenantId', 'name'], { unique: true })
export class Credential {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  tenantId!: string;

  @Column({ type: 'varchar', length: 128 })
  name!: string;

  @Column({ type: 'varchar', length: 32 })
  kind!: CredentialKind;

  /** Per-CIDR / per-host scope the credential is allowed to be used against. */
  @Column({ type: 'jsonb', default: () => `'[]'` })
  scopeCidrs!: string[];

  /**
   * Connection target (firewall management IP/hostname). Stored alongside
   * the secret because (a) one credential is logically tied to one target
   * and (b) the collector needs both in the same JIT decrypt call.
   * Nullable for non-firewall credentials (SNMP communities, etc.).
   */
  @Column({ type: 'varchar', length: 256, nullable: true })
  host!: string | null;

  /** Pinned TLS leaf-cert SHA-256 fingerprint (hex, no separators). */
  @Column({ type: 'varchar', length: 64, nullable: true })
  tlsFingerprintSha256!: string | null;

  /** Wrapped data-encryption key (envelope). */
  @Column({ type: 'bytea' })
  wrappedDek!: Buffer;

  /** AES-256-GCM ciphertext of the secret. */
  @Column({ type: 'bytea' })
  ciphertext!: Buffer;

  @CreateDateColumn()
  createdAt!: Date;

  @Column({ type: 'timestamptz', nullable: true })
  lastUsedAt!: Date | null;
}
