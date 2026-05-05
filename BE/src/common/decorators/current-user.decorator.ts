import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { JwtPayload } from '../strategies/jwt.strategy';

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): JwtPayload =>
    ctx.switchToHttp().getRequest().user,
);
