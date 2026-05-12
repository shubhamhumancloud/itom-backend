import {
  Controller,
  Get,
  Param,
  Query,
  UnauthorizedException,
} from '@nestjs/common';
import { TenantId } from '../../common/decorators/tenant.decorator';
import { TopologyService } from './topology.service';

/**
 * Read-only topology endpoints. Sit under /v1/discovery alongside the
 * existing scan + collector endpoints — same auth model (tenant
 * context from JWT/middleware).
 */
@Controller('discovery')
export class TopologyController {
  constructor(private readonly topology: TopologyService) {}

  @Get('sites')
  async listSites(@TenantId() tenantId: string | null) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    return this.topology.listSites(tenantId);
  }

  @Get('topology')
  async getTopology(
    @TenantId() tenantId: string | null,
    @Query('siteId') siteId?: string,
  ) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    return this.topology.topology(tenantId, siteId || undefined);
  }

  @Get('devices')
  async listDevices(
    @TenantId() tenantId: string | null,
    @Query('q') q?: string,
    @Query('limit') limit?: string,
  ) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    const n = limit ? Math.min(parseInt(limit, 10) || 100, 500) : 100;
    return this.topology.listDevices(tenantId, q, n);
  }

  @Get('devices/:id')
  async getDevice(
    @TenantId() tenantId: string | null,
    @Param('id') id: string,
  ) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    return this.topology.deviceDetail(tenantId, id);
  }
}
