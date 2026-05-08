import { Controller, Get } from '@nestjs/common';

@Controller()
export class HealthController {
  @Get('health')
  check() {
    return { status: 'ok', time: new Date().toISOString() };
  }

  @Get('healthz')
  healthz() {
    return { ok: true, time: new Date().toISOString() };
  }

  @Get('install-info')
  installInfo() {
    // Per-tenant install commands now come from POST /v1/agents/install-tokens
    // (auth required) — they cannot be served unauthenticated because the
    // tenantId is baked into the binary at install time.
    const itomServerUrl =
      process.env.ITOM_SERVER_URL || process.env.ITOM_PUBLIC_URL || '';
    return {
      itomServerUrl,
      hint: 'Sign in to the dashboard, open Settings, and click "Generate install command".',
    };
  }
}
