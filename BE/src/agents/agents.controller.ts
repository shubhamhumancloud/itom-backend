import {
  Body,
  Controller,
  Get,
  Headers,
  NotFoundException,
  Param,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { AgentsService } from './agents.service';
import { RegisterAgentDto } from './dto/register-agent.dto';
import { HeartbeatDto } from './dto/heartbeat.dto';
import { TenantId } from '../common/decorators/tenant.decorator';

const ALLOWED_BINARIES = new Set([
  'itom-agent-linux-amd64',
  'itom-agent-linux-arm64',
  'itom-agent-darwin-amd64',
  'itom-agent-darwin-arm64',
  'itom-agent-windows-amd64.exe',
]);

@Controller('agents')
export class AgentsController {
  constructor(private readonly agentsService: AgentsService) {}

  @Post('register')
  async register(@Body() body: RegisterAgentDto) {
    return this.agentsService.register(body);
  }

  // Bind every agent currently lacking a tenantId to the caller's tenant.
  // Soft auth — relies on the tenant context middleware. Use only in dev /
  // single-tenant setups; in production gate with a strict guard.
  @Post('claim-orphans')
  async claimOrphans(@TenantId() tenantId: string | null) {
    if (!tenantId) {
      return { updatedAgents: 0, error: 'no tenant context on request' };
    }
    return this.agentsService.claimOrphans(tenantId);
  }

  @Post('heartbeat')
  async heartbeat(
    @Body() body: HeartbeatDto,
    @Headers('x-request-id') requestIdHeader?: string,
  ) {
    return this.agentsService.recordHeartbeat(body, requestIdHeader);
  }

  @Get()
  async list(@TenantId() tenantId: string | null) {
    return this.agentsService.list(tenantId);
  }

  // Serve install.sh — users run:
  //   curl -fsSL http://<server>/v1/agents/install.sh | sh
  // curl does not apply macOS quarantine, so Gatekeeper never blocks the binary.
  @Get('install.sh')
  async installScript(@Res() res: Response) {
    const scriptPath = path.resolve(
      process.env.AGENTS_DIST_PATH || path.join(process.cwd(), 'agents-dist'),
      'install.sh',
    );
    if (!fs.existsSync(scriptPath)) {
      throw new NotFoundException('install.sh not found on server');
    }
    res.setHeader('Content-Type', 'text/plain');
    res.sendFile(scriptPath);
  }

  // Serve pre-built binaries — only whitelisted filenames are allowed.
  @Get('download/:filename')
  async download(@Param('filename') filename: string, @Res() res: Response) {
    if (!ALLOWED_BINARIES.has(filename)) {
      throw new NotFoundException('Binary not found');
    }
    const distPath = path.resolve(
      process.env.AGENTS_DIST_PATH || path.join(process.cwd(), 'agents-dist'),
    );
    const filePath = path.join(distPath, filename);

    // Prevent path traversal — resolved path must stay inside distPath
    if (!filePath.startsWith(distPath + path.sep) && filePath !== distPath) {
      throw new NotFoundException('Binary not found');
    }
    if (!fs.existsSync(filePath)) {
      throw new NotFoundException('Binary not found');
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.sendFile(filePath);
  }

  @Get(':agentId')
  async findOne(
    @Param('agentId') agentId: string,
    @TenantId() tenantId: string | null,
  ) {
    return this.agentsService.findOne(agentId, tenantId);
  }

  @Get(':agentId/heartbeats')
  async heartbeats(
    @Param('agentId') agentId: string,
    @Query('limit') limit = '100',
    @TenantId() tenantId?: string | null,
  ) {
    return this.agentsService.listHeartbeats(
      agentId,
      parseInt(limit, 10),
      tenantId,
    );
  }
}
