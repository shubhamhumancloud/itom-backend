import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AlertRule } from './entities/alert-rule.entity';
import { Alert } from './entities/alert.entity';
import { Incident } from './entities/incident.entity';
import { IncidentEvent } from './entities/incident-event.entity';
import { Agent } from '../agents/agent.entity';
import { Metric } from '../metrics/metric.entity';
import { AlertsService } from './alerts.service';
import { AlertsEvaluatorService } from './alerts-evaluator.service';
import { AlertsController } from './alerts.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      AlertRule,
      Alert,
      Incident,
      IncidentEvent,
      Agent,
      Metric,
    ]),
  ],
  providers: [AlertsService, AlertsEvaluatorService],
  controllers: [AlertsController],
  exports: [AlertsService],
})
export class AlertsModule {}
