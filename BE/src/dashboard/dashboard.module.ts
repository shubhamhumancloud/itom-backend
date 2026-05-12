import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Agent } from '../agents/agent.entity';
import { Metric } from '../metrics/metric.entity';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';

@Module({
  imports: [TypeOrmModule.forFeature([Agent, Metric])],
  controllers: [DashboardController],
  providers: [DashboardService],
})
export class DashboardModule {}
