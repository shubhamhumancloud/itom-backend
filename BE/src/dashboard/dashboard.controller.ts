import { Controller, Get, Query } from '@nestjs/common';
import { DashboardService } from './dashboard.service';
import { TenantId } from '../common/decorators/tenant.decorator';

@Controller('dashboard')
export class DashboardController {
  constructor(private readonly dashboard: DashboardService) {}

  @Get('summary')
  summary(@TenantId() tenantId: string | null) {
    return this.dashboard.summary(tenantId);
  }

  @Get('activity-trend')
  activityTrend(
    @TenantId() tenantId: string | null,
    @Query('days') days = '30',
  ) {
    return this.dashboard.activityTrend(parseInt(days, 10) || 30, tenantId);
  }

  @Get('os-distribution')
  osDistribution(@TenantId() tenantId: string | null) {
    return this.dashboard.osDistribution(tenantId);
  }

  @Get('cpu-by-agent')
  cpuByAgent(
    @TenantId() tenantId: string | null,
    @Query('limit') limit = '8',
  ) {
    return this.dashboard.cpuByAgent(parseInt(limit, 10) || 8, tenantId);
  }
}
