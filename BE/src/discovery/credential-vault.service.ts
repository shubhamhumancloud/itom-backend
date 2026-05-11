import {
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as crypto from 'crypto';
import { Credential, CredentialKind } from './entities/credential.entity';
import { AuditLogService } from './audit-log.service';

/**
 * Envelope encryption:
 *   wrappedDek = AES-256-GCM(masterKey, dek)         -- stored on row
 *   ciphertext = AES-256-GCM(dek,       plaintext)   -- stored on row
 *
 * The master key lives in ITOM_DISCOVERY_MASTER_KEY (32-byte random, base64url
 * or 64 hex chars). Production target: swap the master-key source for AWS
 * KMS / Vault Transit behind the same interface — same envelope semantics,
 * different driver.
 *
 * Both wrappedDek and ciphertext are stored as `iv || ciphertext || tag`
 * (12 + N + 16 bytes) to keep the bytea blob self-contained.
 */

const IV_LEN = 12;
const TAG_LEN = 16;

@Injectable()
export class CredentialVaultService {
  private readonly logger = new Logger(CredentialVaultService.name);
  private readonly masterKey: Buffer;

  constructor(
    @InjectRepository(Credential)
    private readonly creds: Repository<Credential>,
    private readonly audit: AuditLogService,
  ) {
    const raw = process.env.ITOM_DISCOVERY_MASTER_KEY || '';
    const key = decodeKey(raw);
    if (!key) {
      // Dev fallback so the server can still start. Tokens / creds signed
      // with this die on restart — fine for local dev, NEVER for production.
      this.masterKey = crypto.randomBytes(32);
      this.logger.warn(
        'ITOM_DISCOVERY_MASTER_KEY is missing or invalid. Using an ephemeral ' +
          'key — credentials encrypted by this process become unreadable on ' +
          'restart. Set ITOM_DISCOVERY_MASTER_KEY to a 32-byte key (64 hex ' +
          'chars or 43+ base64url chars) in production.',
      );
    } else {
      this.masterKey = key;
    }
  }

  async store(input: {
    tenantId: string;
    actor: string;
    name: string;
    kind: CredentialKind;
    scopeCidrs?: string[];
    plaintext: string;
    host?: string;
    tlsFingerprintSha256?: string;
  }): Promise<Credential> {
    const dek = crypto.randomBytes(32);
    const wrappedDek = aeadEncrypt(this.masterKey, dek);
    const ciphertext = aeadEncrypt(dek, Buffer.from(input.plaintext, 'utf8'));

    const row = this.creds.create({
      tenantId: input.tenantId,
      name: input.name,
      kind: input.kind,
      scopeCidrs: input.scopeCidrs ?? [],
      host: input.host ?? null,
      tlsFingerprintSha256: input.tlsFingerprintSha256 ?? null,
      wrappedDek,
      ciphertext,
    });
    const saved = await this.creds.save(row);

    await this.audit.write({
      tenantId: input.tenantId,
      actor: input.actor,
      action: 'credential.created',
      entityKind: 'credential',
      entityId: saved.id,
      metadata: { name: input.name, kind: input.kind },
    });
    return saved;
  }

  /**
   * Decrypt and return the plaintext. Writes one audit row per call.
   * Caller must zero the returned buffer (or string) ASAP.
   */
  async decrypt(input: {
    tenantId: string;
    actor: string;
    credentialId: string;
  }): Promise<string> {
    const row = await this.creds.findOneBy({
      id: input.credentialId,
      tenantId: input.tenantId,
    });
    if (!row) throw new NotFoundException('credential not found');

    let dek: Buffer;
    try {
      dek = aeadDecrypt(this.masterKey, row.wrappedDek);
    } catch {
      throw new UnauthorizedException(
        'master key cannot unwrap credential DEK (was the key rotated?)',
      );
    }
    let plaintext: Buffer;
    try {
      plaintext = aeadDecrypt(dek, row.ciphertext);
    } catch {
      throw new UnauthorizedException('credential ciphertext failed AEAD verify');
    }
    dek.fill(0);

    row.lastUsedAt = new Date();
    await this.creds.save(row);

    await this.audit.write({
      tenantId: input.tenantId,
      actor: input.actor,
      action: 'credential.decrypted',
      entityKind: 'credential',
      entityId: row.id,
      metadata: { name: row.name },
    });

    return plaintext.toString('utf8');
  }

  /**
   * Collector path — returns everything firewall.Creds needs in one
   * call (host + secret + optional TLS pin). Distinguished from
   * `decrypt` because the audit row labels the actor as
   * `collector:<id>` so the operator can tell apart dashboard-issued
   * decrypts from collector-issued ones.
   *
   * The interpretation of `plaintext` depends on `kind`:
   *   - `firewall_api_key`: bearer token → returned in `apiKey`
   *   - `ssh_password`:     password    → returned in `password`
   *   - others:             returned in `password` (caller decides)
   */
  async decryptForCollector(input: {
    tenantId: string;
    collectorId: string;
    credentialId: string;
  }): Promise<{
    host: string;
    username: string;
    password: string;
    apiKey: string;
    tlsFingerprintSha256: string;
    snmpCommunity: string;
  }> {
    const row = await this.creds.findOneBy({
      id: input.credentialId,
      tenantId: input.tenantId,
    });
    if (!row) throw new NotFoundException('credential not found');

    let dek: Buffer;
    try {
      dek = aeadDecrypt(this.masterKey, row.wrappedDek);
    } catch {
      throw new UnauthorizedException(
        'master key cannot unwrap credential DEK (was the key rotated?)',
      );
    }
    let plaintext: Buffer;
    try {
      plaintext = aeadDecrypt(dek, row.ciphertext);
    } catch {
      throw new UnauthorizedException('credential ciphertext failed AEAD verify');
    }
    dek.fill(0);

    row.lastUsedAt = new Date();
    await this.creds.save(row);

    await this.audit.write({
      tenantId: input.tenantId,
      actor: `collector:${input.collectorId}`,
      action: 'credential.decrypted',
      entityKind: 'credential',
      entityId: row.id,
      metadata: { name: row.name, kind: row.kind },
    });

    const secret = plaintext.toString('utf8');
    plaintext.fill(0);

    return {
      host: row.host ?? '',
      username: '',
      password: row.kind === 'ssh_password' ? secret : '',
      apiKey: row.kind === 'firewall_api_key' ? secret : '',
      tlsFingerprintSha256: row.tlsFingerprintSha256 ?? '',
      snmpCommunity: row.kind === 'snmp_v2c' ? secret : '',
    };
  }

  async list(tenantId: string): Promise<Array<Omit<Credential, 'wrappedDek' | 'ciphertext'>>> {
    const rows = await this.creds.find({
      where: { tenantId },
      select: ['id', 'tenantId', 'name', 'kind', 'scopeCidrs', 'host', 'createdAt', 'lastUsedAt'],
      order: { createdAt: 'DESC' },
    });
    return rows;
  }
}

function decodeKey(raw: string): Buffer | null {
  if (!raw) return null;
  // 64 hex chars
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
  // base64url, anything decoding to 32 bytes
  try {
    const padded = raw.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (padded.length % 4)) % 4;
    const buf = Buffer.from(padded + '='.repeat(padLen), 'base64');
    if (buf.length === 32) return buf;
  } catch {
    /* ignore */
  }
  return null;
}

function aeadEncrypt(key: Buffer, plaintext: Buffer): Buffer {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]);
}

function aeadDecrypt(key: Buffer, blob: Buffer): Buffer {
  if (blob.length < IV_LEN + TAG_LEN) throw new Error('blob too short');
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const ct = blob.subarray(IV_LEN, blob.length - TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
