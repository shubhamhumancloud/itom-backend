import { Injectable, NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

declare module 'express' {
  interface Request {
    tenantId?: string | null;
    jwtClaims?: Record<string, unknown>;
  }
}

function decodePayload(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split('.')[1];
    if (!payload) return null;
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '==='.slice((normalized.length + 3) % 4);
    const decoded = Buffer.from(padded, 'base64').toString('utf8');
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

@Injectable()
export class TenantContextMiddleware implements NestMiddleware {
  use(req: Request, _res: Response, next: NextFunction) {
    const auth = req.headers['authorization'];
    if (typeof auth === 'string' && auth.toLowerCase().startsWith('bearer ')) {
      const token = auth.slice(7).trim();
      const claims = decodePayload(token);
      if (claims) {
        req.jwtClaims = claims;
        const tid =
          (claims.tenantId as string | undefined) ??
          (claims.tid as string | undefined) ??
          null;
        req.tenantId = tid ?? null;
      }
    }
    next();
  }
}
