import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Agent } from './agent.entity';
import { AgentHeartbeat } from './agent-heartbeat.entity';
import { RequestDedup } from './request-dedup.entity';
import { AgentsController } from './agents.controller';
import { AgentsService } from './agents.service';
import { AgentsSchedulerService } from './agents-scheduler.service';
import { AgentsGateway } from './ws/agents.gateway';
import { MetricsModule } from '../metrics/metrics.module';
import { ObservabilityModule } from '../observability/observability.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Agent, AgentHeartbeat, RequestDedup]),
    MetricsModule,
    forwardRef(() => ObservabilityModule),
  ],
  controllers: [AgentsController],
  providers: [AgentsService, AgentsSchedulerService, AgentsGateway],
  exports: [AgentsService, AgentsGateway],
})
export class AgentsModule {}
