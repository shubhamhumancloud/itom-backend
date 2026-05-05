import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';

@Injectable()
export class InternalApiKeyGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    const provided = req.headers['x-internal-api-key'];
    const expected = process.env.INTERNAL_API_KEY;

    if (!expected) {
      throw new UnauthorizedException('Internal API key not configured');
    }
    if (!provided || provided !== expected) {
      throw new UnauthorizedException('Invalid internal API key');
    }
    return true;
  }
}
