import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScheduleModule } from '@nestjs/schedule';

import { MetricsModule } from './metrics/metrics.module';
import { AgentsModule } from './agents/agents.module';
import { HealthController } from './health/health.controller';
import { Metric } from './metrics/metric.entity';
import { NetworkMetric } from './metrics/network-metric.entity';
import { DiskMetric } from './metrics/disk-metric.entity';
import { Agent } from './agents/agent.entity';
import { AgentHeartbeat } from './agents/agent-heartbeat.entity';
import { RequestDedup } from './agents/request-dedup.entity';
import { AuthModule } from './common/auth.module';
import { OnboardingModule } from './modules/onboarding/onboarding.module';
import { DashboardModule } from './dashboard/dashboard.module';
import { Tenant } from './modules/onboarding/tenant.entity';
import { TenantUser } from './modules/onboarding/tenant-user.entity';
import { TenantContextMiddleware } from './common/tenant-context.middleware';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      username: process.env.DB_USER || 'itom',
      password: process.env.DB_PASSWORD || 'itom',
      database: process.env.DB_NAME || 'itom',
      entities: [
        Metric,
        NetworkMetric,
        DiskMetric,
        Agent,
        AgentHeartbeat,
        RequestDedup,
        Tenant,
        TenantUser,
      ],
      synchronize: true,
      logging: process.env.DB_LOGGING === 'true',
    }),
    AuthModule,
    MetricsModule,
    AgentsModule,
    OnboardingModule,
    DashboardModule,
  ],
  controllers: [HealthController],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TenantContextMiddleware).forRoutes('*');
  }
}
