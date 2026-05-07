import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ProcessMetric } from './entities/process-metric.entity';
import { BatteryMetric } from './entities/battery-metric.entity';
import { SensorMetric } from './entities/sensor-metric.entity';
import { DiskHealth } from './entities/disk-health.entity';
import { GpuMetric } from './entities/gpu-metric.entity';
import { SoftwareItem } from './entities/software-item.entity';
import { ObservabilityService } from './observability.service';
import { ObservabilityController } from './observability.controller';
import { AgentsModule } from '../agents/agents.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      ProcessMetric,
      BatteryMetric,
      SensorMetric,
      DiskHealth,
      GpuMetric,
      SoftwareItem,
    ]),
    forwardRef(() => AgentsModule),
  ],
  providers: [ObservabilityService],
  controllers: [ObservabilityController],
  exports: [ObservabilityService],
})
export class ObservabilityModule {}
