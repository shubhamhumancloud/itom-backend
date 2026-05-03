import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Metric } from './metric.entity';
import { NetworkMetric } from './network-metric.entity';
import { DiskMetric } from './disk-metric.entity';
import { MetricsController } from './metrics.controller';
import { MetricsService } from './metrics.service';
import { Agent } from '../agents/agent.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Metric, NetworkMetric, DiskMetric, Agent]),
  ],
  controllers: [MetricsController],
  providers: [MetricsService],
})
export class MetricsModule {}
