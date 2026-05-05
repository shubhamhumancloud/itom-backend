import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';

@Injectable()
export class TenantGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    const user = req.user;
    const tenantId = user?.tenantId;

    if (!tenantId) {
      throw new ForbiddenException('Token is missing tenant context');
    }

    const paramTenant = req.params?.tenantId;
    if (paramTenant && paramTenant !== tenantId) {
      throw new ForbiddenException('Tenant mismatch');
    }

    req.tenantId = tenantId;
    return true;
  }
}
