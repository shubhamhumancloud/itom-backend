import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import type { Request } from 'express';
import { AlertsService } from './alerts.service';
import { TenantId } from '../common/decorators/tenant.decorator';

/**
 * REST surface for the alerts/incidents module. Global prefix `v1` applies,
 * so these resolve to /v1/alerts, /v1/incidents, /v1/alert-rules.
 */
@Controller()
export class AlertsController {
  constructor(private readonly alerts: AlertsService) {}

  @Get('alerts')
  listAlerts(
    @TenantId() tenantId: string | null,
    @Query('state') state?: string,
    @Query('severity') severity?: string,
    @Query('agentId') agentId?: string,
  ) {
    return this.alerts.listAlerts(tenantId, { state, severity, agentId });
  }

  @Get('alerts/summary')
  summary(@TenantId() tenantId: string | null) {
    return this.alerts.summary(tenantId);
  }

  @Get('alert-rules')
  listRules(@TenantId() tenantId: string | null) {
    return this.alerts.listRules(tenantId);
  }

  /**
   * Update a rule's thresholds / window / enabled flag. A tenant editing a
   * global rule forks a tenant-scoped override (see AlertsService).
   */
  @Patch('alert-rules/:id')
  updateRule(
    @Param('id') id: string,
    @TenantId() tenantId: string | null,
    @Body()
    body: {
      warningThreshold?: number | null;
      criticalThreshold?: number | null;
      recoveryThreshold?: number | null;
      forSeconds?: number;
      enabled?: boolean;
    },
  ) {
    return this.alerts.updateRule(id, tenantId, body ?? {});
  }

  /** Drop a tenant override so the global default applies again. */
  @Post('alert-rules/:id/reset')
  resetRule(
    @Param('id') id: string,
    @TenantId() tenantId: string | null,
  ) {
    return this.alerts.resetRule(id, tenantId);
  }

  @Get('incidents')
  listIncidents(
    @TenantId() tenantId: string | null,
    @Query('status') status?: string,
  ) {
    return this.alerts.listIncidents(tenantId, status);
  }

  @Get('incidents/:id')
  getIncident(
    @Param('id') id: string,
    @TenantId() tenantId: string | null,
  ) {
    return this.alerts.getIncident(id, tenantId);
  }

  @Post('incidents/:id/acknowledge')
  acknowledge(
    @Param('id') id: string,
    @TenantId() tenantId: string | null,
    @Req() req: Request,
  ) {
    return this.alerts.acknowledgeIncident(id, tenantId, actorOf(req));
  }

  @Post('incidents/:id/resolve')
  resolve(
    @Param('id') id: string,
    @TenantId() tenantId: string | null,
    @Req() req: Request,
  ) {
    return this.alerts.resolveIncident(id, tenantId, actorOf(req));
  }

  @Post('incidents/:id/comment')
  comment(
    @Param('id') id: string,
    @TenantId() tenantId: string | null,
    @Body('message') message: string,
    @Req() req: Request,
  ) {
    return this.alerts.commentIncident(
      id,
      tenantId,
      actorOf(req),
      (message ?? '').trim() || '(empty comment)',
    );
  }
}

/** Best-effort actor label from the JWT claims the middleware decoded. */
function actorOf(req: Request): string {
  const claims = req.jwtClaims ?? {};
  return String(
    claims.email ?? claims.name ?? claims.sub ?? 'unknown user',
  );
}
