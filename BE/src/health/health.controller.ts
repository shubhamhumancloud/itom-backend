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
    const itomServerUrl = process.env.ITOM_SERVER_URL || 'http://localhost:3007';
    return {
      itomServerUrl,
      unixCurl: `curl -fsSL ${itomServerUrl}/v1/agents/install.sh | sh`,
      windowsPowerShell: `iwr ${itomServerUrl}/v1/agents/download/itom-agent-windows-amd64.exe -OutFile itom-agent.exe`,
    };
  }
}
