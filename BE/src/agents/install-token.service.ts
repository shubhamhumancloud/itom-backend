import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';

/**
 * Install tokens gate the per-tenant agent download. They are minted by an
 * authenticated dashboard request, embedded in the install URL, and verified
 * by the public download endpoint. Once expired (default 1h) the URL is
 * dead — re-mint another from the dashboard.
 *
 * Format: base64url(payload).base64url(hmacSha256(secret, payload))
 *
 * The shape is JWT-ish but we don't pull in a JWT library — symmetric HMAC
 * signing is plenty for a same-system signer/verifier and avoids one more
 * dependency.
 */

export interface InstallTokenPayload {
  tenantId: string;
  exp: number; // epoch seconds
  iat: number; // epoch seconds
  purpose: 'install';
}

@Injectable()
export class InstallTokenService {
  private readonly logger = new Logger(InstallTokenService.name);
  private readonly secret: Buffer;
  private readonly defaultTtlSeconds: number;

  constructor() {
    const raw = process.env.ITOM_INSTALL_TOKEN_SECRET;
    if (!raw || raw.length < 32) {
      // Generate an ephemeral key in dev so the server still starts. Tokens
      // signed with it die when the process restarts — which is correct
      // behaviour for an unconfigured dev environment.
      const ephemeral = crypto.randomBytes(32);
      this.secret = ephemeral;
      this.logger.warn(
        'ITOM_INSTALL_TOKEN_SECRET is not set or too short (need ≥32 chars). ' +
          'Using an ephemeral key — tokens minted by this process die on restart. ' +
          'Set ITOM_INSTALL_TOKEN_SECRET to a 32+ char random string in production.',
      );
    } else {
      this.secret = Buffer.from(raw, 'utf8');
    }

    const ttl = parseInt(process.env.ITOM_INSTALL_TOKEN_TTL_SECONDS || '', 10);
    this.defaultTtlSeconds =
      Number.isFinite(ttl) && ttl > 60 && ttl <= 24 * 3600 ? ttl : 3600;
  }

  mint(tenantId: string, ttlSeconds?: number): {
    token: string;
    expiresAt: string;
  } {
    if (!tenantId) {
      throw new Error('cannot mint install token without tenantId');
    }
    const now = Math.floor(Date.now() / 1000);
    const ttl = ttlSeconds && ttlSeconds > 0 ? ttlSeconds : this.defaultTtlSeconds;
    const payload: InstallTokenPayload = {
      tenantId,
      iat: now,
      exp: now + ttl,
      purpose: 'install',
    };

    const payloadB64 = base64urlEncode(Buffer.from(JSON.stringify(payload)));
    const sig = this.sign(payloadB64);
    return {
      token: `${payloadB64}.${sig}`,
      expiresAt: new Date(payload.exp * 1000).toISOString(),
    };
  }

  /**
   * Verify a token and return its payload. Throws UnauthorizedException on
   * bad signature, expiry, or any structural problem.
   *
   * We strip any trailing non-base64url characters before verification.
   * Quote characters (' or ") sometimes survive a shell paste only to be
   * URL-encoded into %27 / %22 by a clipboard helper or browser address
   * bar, ending up appended to the token. Legitimate tokens are pure
   * [A-Za-z0-9._-], so stripping trailing junk is safe.
   */
  verify(rawToken: string): InstallTokenPayload {
    if (typeof rawToken !== 'string') {
      throw new UnauthorizedException('invalid install token');
    }
    const token = rawToken.replace(/[^A-Za-z0-9._-]+$/, '');
    if (!token.includes('.')) {
      throw new UnauthorizedException('invalid install token');
    }
    const [payloadB64, sig] = token.split('.');
    if (!payloadB64 || !sig) {
      throw new UnauthorizedException('invalid install token');
    }
    const expectedSig = this.sign(payloadB64);
    if (!constantTimeEq(sig, expectedSig)) {
      throw new UnauthorizedException('invalid install token signature');
    }

    let payload: InstallTokenPayload;
    try {
      const json = base64urlDecode(payloadB64).toString('utf8');
      payload = JSON.parse(json);
    } catch {
      throw new UnauthorizedException('invalid install token payload');
    }
    if (payload.purpose !== 'install') {
      throw new UnauthorizedException('invalid install token purpose');
    }
    if (
      typeof payload.tenantId !== 'string' ||
      typeof payload.exp !== 'number' ||
      typeof payload.iat !== 'number'
    ) {
      throw new UnauthorizedException('invalid install token shape');
    }
    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp < nowSec) {
      throw new UnauthorizedException('install token expired');
    }
    return payload;
  }

  private sign(payloadB64: string): string {
    const mac = crypto.createHmac('sha256', this.secret);
    mac.update(payloadB64);
    return base64urlEncode(mac.digest());
  }
}

function base64urlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(s: string): Buffer {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + '='.repeat(padLen), 'base64');
}

function constantTimeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return crypto.timingSafeEqual(ab, bb);
}
