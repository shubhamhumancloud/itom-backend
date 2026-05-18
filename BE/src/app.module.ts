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
import { AgentStatusEvent } from './agents/agent-status-event.entity';
import { RequestDedup } from './agents/request-dedup.entity';
import { AuthModule } from './common/auth.module';
import { OnboardingModule } from './modules/onboarding/onboarding.module';
import { DashboardModule } from './dashboard/dashboard.module';
import { Tenant } from './modules/onboarding/tenant.entity';
import { TenantUser } from './modules/onboarding/tenant-user.entity';
import { TenantContextMiddleware } from './common/tenant-context.middleware';
import { ObservabilityModule } from './observability/observability.module';
import { ProcessMetric } from './observability/entities/process-metric.entity';
import { BatteryMetric } from './observability/entities/battery-metric.entity';
import { SensorMetric } from './observability/entities/sensor-metric.entity';
import { GpuMetric } from './observability/entities/gpu-metric.entity';
import { SoftwareItem } from './observability/entities/software-item.entity';
import { DiscoveryModule } from './discovery/discovery.module';
import { AlertsModule } from './alerts/alerts.module';
import { AlertRule } from './alerts/entities/alert-rule.entity';
import { Alert } from './alerts/entities/alert.entity';
import { Incident } from './alerts/entities/incident.entity';
import { IncidentEvent } from './alerts/entities/incident-event.entity';
import { ScanJob } from './discovery/entities/scan-job.entity';
import { DiscoverySession } from './discovery/entities/discovery-session.entity';
import { Observation } from './discovery/entities/observation.entity';
import { Credential } from './discovery/entities/credential.entity';
import { AuditLog } from './discovery/entities/audit-log.entity';
import { Collector } from './discovery/entities/collector.entity';
import { Site } from './discovery/entities/site.entity';
import { Device } from './discovery/entities/device.entity';
import { NetworkInterface } from './discovery/entities/network-interface.entity';
import { IpBinding } from './discovery/entities/ip-binding.entity';
import { NeighborEdge } from './discovery/entities/neighbor-edge.entity';
import { OpenPort } from './discovery/entities/open-port.entity';
import { DiscoveryEvent } from './discovery/entities/discovery-event.entity';

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
        AgentStatusEvent,
        RequestDedup,
        Tenant,
        TenantUser,
        ProcessMetric,
        BatteryMetric,
        SensorMetric,
        GpuMetric,
        SoftwareItem,
        ScanJob,
        DiscoverySession,
        Observation,
        Credential,
        AuditLog,
        Collector,
        Site,
        Device,
        NetworkInterface,
        IpBinding,
        NeighborEdge,
        OpenPort,
        DiscoveryEvent,
        AlertRule,
        Alert,
        Incident,
        IncidentEvent,
      ],
      synchronize: true,
      logging: process.env.DB_LOGGING === 'true',
    }),
    AuthModule,
    MetricsModule,
    AgentsModule,
    OnboardingModule,
    DashboardModule,
    ObservabilityModule,
    DiscoveryModule,
    AlertsModule,
  ],
  controllers: [HealthController],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TenantContextMiddleware).forRoutes('*');
  }
}
