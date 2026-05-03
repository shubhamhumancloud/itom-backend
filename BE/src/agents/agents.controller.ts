import {
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  Post,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { AgentsService } from './agents.service';
import { RegisterAgentDto } from './dto/register-agent.dto';

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

  @Get()
  async list() {
    return this.agentsService.list();
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
  async findOne(@Param('agentId') agentId: string) {
    return this.agentsService.findOne(agentId);
  }
}
