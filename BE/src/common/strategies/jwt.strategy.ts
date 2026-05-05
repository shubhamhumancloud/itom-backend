import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { passportJwtSecret } from 'jwks-rsa';

export interface JwtPayload {
  sub: string;
  email?: string;
  tenantId?: string;
  orgId?: string;
  appId?: string;
  roles?: string[];
  permissions?: string[];
  [key: string]: any;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    const jwksUri = process.env.SSO_JWKS_URL;
    if (!jwksUri) {
      throw new Error('SSO_JWKS_URL is not configured');
    }
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider: passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 10,
        jwksUri,
      }),
      algorithms: ['RS256'],
    });
  }

  async validate(payload: JwtPayload): Promise<JwtPayload> {
    if (!payload?.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }
    return payload;
  }
}
