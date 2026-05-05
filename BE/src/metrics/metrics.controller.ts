import {
  Body,
  Controller,
  Get,
  Headers,
  Post,
  Query,
} from '@nestjs/common';
import { MetricsService } from './metrics.service';
import { CreateMetricsDto } from './dto/create-metrics.dto';
import { TenantId } from '../common/decorators/tenant.decorator';

@Controller('metrics')
export class MetricsController {
  constructor(private readonly metricsService: MetricsService) {}

  // Declare specific routes before parameterised ones so the router resolves them.
  @Get('agents')
  async agents(@TenantId() tenantId: string | null) {
    return this.metricsService.listAgents(tenantId);
  }

  @Post()
  async ingest(
    @Body() body: CreateMetricsDto,
    @Headers('x-request-id') requestIdHeader?: string,
  ) {
    const result = await this.metricsService.ingest(body, requestIdHeader);
    if (typeof result === 'object' && result !== null && 'reason' in result) {
      return result;
    }
    return { accepted: result as number };
  }

  @Get()
  async list(
    @Query('agentId') agentId: string,
    @TenantId() tenantId: string | null,
    @Query('limit') limit = '100',
  ) {
    return this.metricsService.list(agentId, parseInt(limit, 10), tenantId);
  }

  @Get('network')
  async network(
    @TenantId() tenantId: string | null,
    @Query('agentId') agentId?: string,
    @Query('interfaceName') interfaceName?: string,
    @Query('limit') limit = '200',
  ) {
    return this.metricsService.listNetwork(
      agentId,
      interfaceName,
      parseInt(limit, 10),
      tenantId,
    );
  }

  @Get('disk')
  async disk(
    @TenantId() tenantId: string | null,
    @Query('agentId') agentId?: string,
    @Query('limit') limit = '100',
  ) {
    return this.metricsService.listDisk(agentId, parseInt(limit, 10), tenantId);
  }
}
