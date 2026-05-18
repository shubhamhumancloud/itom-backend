import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { AlertsService } from './alerts.service';

/**
 * Thin cron wrapper around AlertsService.runEvaluation().
 *
 * Runs every 60s — aligned with the agent flush cadence (agents batch
 * their 10s samples and POST every ~60s, so evaluating faster than that
 * just re-reads the same data).
 */
@Injectable()
export class AlertsEvaluatorService {
  private readonly logger = new Logger(AlertsEvaluatorService.name);
  private running = false;

  constructor(private readonly alerts: AlertsService) {}

  @Cron('*/60 * * * * *')
  async tick(): Promise<void> {
    if (this.running) {
      this.logger.warn('previous evaluation still running — skipping tick');
      return;
    }
    this.running = true;
    try {
      await this.alerts.runEvaluation();
    } catch (err) {
      this.logger.error(`evaluation tick failed: ${String(err)}`);
    } finally {
      this.running = false;
    }
  }
}
