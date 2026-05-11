import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as crypto from 'crypto';

/**
 * Ed25519 signer for the per-tenant CIDR allowlist. The collector holds
 * the matching public key and refuses any `scan_job.assign` whose
 * signature does not verify. This is defence in depth: a bug in
 * scan-job dispatch that sends the wrong allowlist must NOT make the
 * collector scan outside the tenant's scope.
 *
 * Key sourcing:
 *   - Production: read base64-encoded private key from
 *     ITOM_DISCOVERY_CIDR_PRIVATE_KEY. The matching public key is
 *     baked into every collector binary at install time.
 *   - Dev (no env var): generate an ephemeral keypair on boot and log
 *     the public key. Useful for local round-trips; restart of the BE
 *     invalidates every active collector's verification until you set
 *     the env var.
 *
 * The signed message is the canonical bytes from `canonicalAllowlist`
 * — this MUST match `cidrguard.CanonicalBytes` in the Go collector
 * byte-for-byte.
 */
@Injectable()
export class SigningService implements OnModuleInit {
  private readonly logger = new Logger(SigningService.name);
  private privateKey!: crypto.KeyObject;
  private publicKeyBase64!: string;

  onModuleInit() {
    const raw = process.env.ITOM_DISCOVERY_CIDR_PRIVATE_KEY?.trim();
    if (raw) {
      this.loadFromBase64(raw);
    } else {
      this.generateEphemeral();
    }
  }

  /**
   * Sign a CIDR allowlist. Returns a base64 Ed25519 signature.
   *
   * Callers (scan-job dispatch) pass the same array that ships in
   * `ScanJobAssign.allowlistCidrs`; we canonicalise here so callers
   * cannot accidentally sign a different shape than the collector
   * verifies.
   */
  signAllowlist(cidrs: string[]): { signature: string; cidrs: string[] } {
    const sorted = [...cidrs].sort();
    const message = canonicalAllowlist(sorted);
    const sig = crypto.sign(null, message, this.privateKey);
    return { signature: sig.toString('base64'), cidrs: sorted };
  }

  /** Expose the public key (base64) so an admin endpoint can return it
   *  to the collector installer / dashboard. */
  getPublicKeyBase64(): string {
    return this.publicKeyBase64;
  }

  // -----------------------------------------------------------------

  private loadFromBase64(privB64: string): void {
    // We accept either:
    //   - the 32-byte raw seed (base64) — what `openssl genpkey | head`
    //     produces if you strip the PEM wrapper; or
    //   - a base64-encoded DER PKCS#8 Ed25519 key.
    // Both are common; tolerate both so the operator picks whichever
    // their key management produces.
    const buf = Buffer.from(privB64, 'base64');
    try {
      this.privateKey =
        buf.length === 32
          ? crypto.createPrivateKey({
              key: rawSeedToPkcs8(buf),
              format: 'der',
              type: 'pkcs8',
            })
          : crypto.createPrivateKey({
              key: buf,
              format: 'der',
              type: 'pkcs8',
            });
    } catch (e: any) {
      this.logger.error(
        `failed to load CIDR private key: ${e.message}. Falling back to an ephemeral key — collectors will refuse to verify until ITOM_DISCOVERY_CIDR_PRIVATE_KEY is fixed.`,
      );
      this.generateEphemeral();
      return;
    }
    const pub = crypto.createPublicKey(this.privateKey);
    this.publicKeyBase64 = extractRawEd25519PublicKey(pub).toString('base64');
    this.logger.log(`CIDR signer ready (publicKey=${this.publicKeyBase64})`);
  }

  private generateEphemeral(): void {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyBase64 = extractRawEd25519PublicKey(publicKey).toString('base64');
    this.logger.warn(
      'ITOM_DISCOVERY_CIDR_PRIVATE_KEY is unset — generated an ephemeral keypair. ' +
        'For production set the env var; otherwise every BE restart invalidates ' +
        'all collector signature verification. Ephemeral publicKey=' +
        this.publicKeyBase64,
    );
  }
}

/**
 * Canonical byte serialisation of the allowlist. MUST stay byte-for-
 * byte identical to `cidrguard.CanonicalBytes` in
 * backend/collector/internal/cidrguard/cidrguard.go.
 *
 * Format:  {"v":1,"cidrs":["a","b",...]}
 * - cidrs is the alphabetically sorted input
 * - JSON.stringify with no whitespace; the field order matches the
 *   Go canonical struct (Version then CIDRs).
 */
export function canonicalAllowlist(sortedCidrs: string[]): Buffer {
  return Buffer.from(
    JSON.stringify({ v: 1, cidrs: sortedCidrs }),
    'utf8',
  );
}

// ---------- key encoding helpers ----------

// DER PKCS#8 prefix for an Ed25519 private key (RFC 8410 §7):
//   30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32-byte seed>
const PKCS8_ED25519_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex',
);

function rawSeedToPkcs8(seed: Buffer): Buffer {
  if (seed.length !== 32) throw new Error('ed25519 seed must be 32 bytes');
  return Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
}

// SPKI Ed25519 public key prefix:
//   30 2a 30 05 06 03 2b 65 70 03 21 00 <32-byte pubkey>
const SPKI_ED25519_PREFIX_LEN = 12;

function extractRawEd25519PublicKey(pub: crypto.KeyObject): Buffer {
  const spki = pub.export({ format: 'der', type: 'spki' });
  // The last 32 bytes of an Ed25519 SPKI export are the raw pubkey.
  if (spki.length < SPKI_ED25519_PREFIX_LEN + 32) {
    throw new Error(`unexpected SPKI length ${spki.length}`);
  }
  return spki.subarray(spki.length - 32);
}
