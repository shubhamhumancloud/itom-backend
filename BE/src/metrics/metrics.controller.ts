import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { MetricsService } from './metrics.service';
import { CreateMetricsDto } from './dto/create-metrics.dto';

@Controller('metrics')
export class MetricsController {
  constructor(private readonly metricsService: MetricsService) {}

  // Note: declare specific routes (`/agents`) before parameterised ones
  // so the router resolves them correctly.
  @Get('agents')
  async agents() {
    return this.metricsService.listAgents();
  }

  @Post()
  async ingest(@Body() body: CreateMetricsDto) {
    const accepted = await this.metricsService.ingest(body);
    return { accepted };
  }

  @Get()
  async list(
    @Query('agentId') agentId: string,
    @Query('limit') limit = '100',
  ) {
    return this.metricsService.list(agentId, parseInt(limit, 10));
  }
}
