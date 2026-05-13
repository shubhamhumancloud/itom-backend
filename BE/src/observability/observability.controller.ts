import { Controller, Get, Param, Query } from '@nestjs/common';
import { ObservabilityService } from './observability.service';
import { TenantId } from '../common/decorators/tenant.decorator';
import { AgentsService } from '../agents/agents.service';

@Controller('agents/:agentId')
export class ObservabilityController {
  constructor(
    private readonly obs: ObservabilityService,
    private readonly agents: AgentsService,
  ) {}

  // ---------- Processes ----------

  @Get('processes')
  async processes(
    @Param('agentId') agentId: string,
    @TenantId() tenantId: string | null,
    @Query('limit') limit = '100',
  ) {
    if (!(await this.canRead(agentId, tenantId))) return [];
    return this.obs.latestProcesses(agentId, parseInt(limit, 10));
  }

  @Get('processes/sparklines')
  async processSparklines(
    @Param('agentId') agentId: string,
    @TenantId() tenantId: string | null,
    @Query('names') names = '',
    @Query('points') points = '30',
  ) {
    if (!(await this.canRead(agentId, tenantId))) return {};
    const list = names.split(',').filter(Boolean).slice(0, 50);
    return this.obs.processSeriesBulk(agentId, list, parseInt(points, 10));
  }

  // ---------- Battery ----------

  @Get('battery')
  async battery(
    @Param('agentId') agentId: string,
    @TenantId() tenantId: string | null,
    @Query('limit') limit = '100',
  ) {
    if (!(await this.canRead(agentId, tenantId))) return [];
    return this.obs.batteryHistory(agentId, parseInt(limit, 10));
  }

  // ---------- Sensors (CPU temp + fan) ----------

  @Get('sensors')
  async sensors(
    @Param('agentId') agentId: string,
    @TenantId() tenantId: string | null,
    @Query('kind') kind?: 'temperature_c' | 'fan_rpm',
    @Query('limit') limit = '200',
  ) {
    if (!(await this.canRead(agentId, tenantId))) return [];
    return this.obs.sensorHistory(agentId, kind, parseInt(limit, 10));
  }

  // ---------- GPU ----------

  @Get('gpu')
  async gpuLatest(
    @Param('agentId') agentId: string,
    @TenantId() tenantId: string | null,
  ) {
    if (!(await this.canRead(agentId, tenantId))) return [];
    return this.obs.latestGpu(agentId);
  }

  @Get('gpu/history')
  async gpuHistory(
    @Param('agentId') agentId: string,
    @TenantId() tenantId: string | null,
    @Query('limit') limit = '120',
  ) {
    if (!(await this.canRead(agentId, tenantId))) return [];
    return this.obs.gpuHistory(agentId, parseInt(limit, 10));
  }

  // ---------- Software inventory ----------

  @Get('software')
  async software(
    @Param('agentId') agentId: string,
    @TenantId() tenantId: string | null,
    @Query('search') search?: string,
    @Query('cursor') cursor?: string,
    @Query('limit') limit = '50',
  ) {
    if (!(await this.canRead(agentId, tenantId))) {
      return { items: [], nextCursor: null };
    }
    return this.obs.listSoftware(agentId, {
      search: search?.trim() || undefined,
      cursor: cursor || undefined,
      limit: parseInt(limit, 10),
    });
  }

  // Tenant scope guard — same pattern other controllers use.
  private async canRead(
    agentId: string,
    tenantId: string | null,
  ): Promise<boolean> {
    if (!tenantId) return true;
    const a = await this.agents.findOne(agentId, tenantId);
    return !!a;
  }
}
