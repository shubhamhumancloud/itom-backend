import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Metric } from './metric.entity';
import { NetworkMetric } from './network-metric.entity';
import { DiskMetric } from './disk-metric.entity';
import { MetricsController } from './metrics.controller';
import { MetricsService } from './metrics.service';
import { AgentsModule } from '../agents/agents.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Metric, NetworkMetric, DiskMetric]),
    AgentsModule,
  ],
  controllers: [MetricsController],
  providers: [MetricsService],
})
export class MetricsModule {}
