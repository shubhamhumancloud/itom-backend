import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { MetricsModule } from './metrics/metrics.module';
import { AgentsModule } from './agents/agents.module';
import { HealthController } from './health/health.controller';
import { Metric } from './metrics/metric.entity';
import { NetworkMetric } from './metrics/network-metric.entity';
import { DiskMetric } from './metrics/disk-metric.entity';
import { Agent } from './agents/agent.entity';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      username: process.env.DB_USER || 'itom',
      password: process.env.DB_PASSWORD || 'itom',
      database: process.env.DB_NAME || 'itom',
      entities: [Metric, NetworkMetric, DiskMetric, Agent],
      synchronize: true,
      logging: process.env.DB_LOGGING === 'true',
    }),
    MetricsModule,
    AgentsModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
