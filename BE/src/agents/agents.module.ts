import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Agent } from './agent.entity';
import { AgentHeartbeat } from './agent-heartbeat.entity';
import { RequestDedup } from './request-dedup.entity';
import { AgentsController } from './agents.controller';
import { AgentsService } from './agents.service';
import { AgentsSchedulerService } from './agents-scheduler.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Agent, AgentHeartbeat, RequestDedup]),
  ],
  controllers: [AgentsController],
  providers: [AgentsService, AgentsSchedulerService],
  exports: [AgentsService],
})
export class AgentsModule {}
