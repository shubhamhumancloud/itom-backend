import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  NotFoundException,
  Param,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AgentsService } from './agents.service';
import { RegisterAgentDto } from './dto/register-agent.dto';
import { HeartbeatDto } from './dto/heartbeat.dto';
import { TenantId } from '../common/decorators/tenant.decorator';
import { InstallTokenService } from './install-token.service';
import {
  BinaryPatcherService,
  SupportedArch,
  SupportedOS,
} from './binary-patcher.service';
import { InstallScriptService } from './install-script.service';

const SUPPORTED_OS: ReadonlySet<SupportedOS> = new Set(['linux', 'darwin', 'windows']);
const SUPPORTED_ARCH: ReadonlySet<SupportedArch> = new Set(['amd64', 'arm64']);

@Controller('agents')
export class AgentsController {
  constructor(
    private readonly agentsService: AgentsService,
    private readonly installTokens: InstallTokenService,
    private readonly patcher: BinaryPatcherService,
    private readonly installScripts: InstallScriptService,
  ) {}

  @Post('register')
  async register(@Body() body: RegisterAgentDto) {
    return this.agentsService.register(body);
  }

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

  // ---------------------------------------------------------------------
  // Per-tenant install flow
  // ---------------------------------------------------------------------

  /**
   * Mint a short-lived install token for the calling tenant. The dashboard
   * embeds the returned token in the install one-liner shown to the user.
   * Token TTL is 1h by default.
   */
  @Post('install-tokens')
  async createInstallToken(
    @TenantId() tenantId: string | null,
    @Req() req: Request,
  ) {
    if (!tenantId) {
      throw new UnauthorizedException(
        'install tokens require an authenticated tenant context',
      );
    }
    const { token, expiresAt } = this.installTokens.mint(tenantId);
    const publicUrl = resolvePublicUrl(req);
    return {
      token,
      expiresAt,
      tenantId,
      publicUrl,
      commands: {
        // Linux & macOS — single-line installer. Single-quoted on purpose:
        // double-quoted URLs survive most clipboard paths but some tools
        // re-encode trailing " into %22 and break the command. Single
        // quotes are literal everywhere (bash/sh/zsh/dash).
        sh: `curl -fsSL '${publicUrl}/v1/agents/install?token=${encodeURIComponent(token)}' | sudo sh`,
        // Windows — wrapped in a `powershell -NoProfile -Command "..."`
        // launcher so the same one-liner works whether the user pastes it
        // into cmd.exe, PowerShell, or the Run dialog. The inner script
        // uses single-quoted URL (PS literal) so the embedded `&` in the
        // query string is treated as part of the URL, not a PS operator.
        // The agent itself checks for admin privileges and errors out
        // with a helpful message if the shell isn't elevated.
        ps1: `powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr '${publicUrl}/v1/agents/install?token=${encodeURIComponent(token)}&platform=ps1' -UseBasicParsing | iex"`,
      },
    };
  }

  /**
   * Render the per-platform install script with the build URL embedded.
   * Public — gated entirely by the token in the query string.
   */
  @Get('install')
  async renderInstallScript(
    @Query('token') token: string,
    @Query('platform') platform: 'sh' | 'ps1' | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const payload = this.installTokens.verify(token);
    const publicUrl = resolvePublicUrl(req);
    const useShell = platform !== 'ps1';
    const body = useShell
      ? this.installScripts.renderShell(publicUrl, token)
      : this.installScripts.renderPowerShell(publicUrl, token);

    res.setHeader('Content-Type', useShell ? 'text/plain' : 'text/plain');
    // Encourage the client to actually pipe it (no caching, no detection).
    res.setHeader('Cache-Control', 'no-store');
    // For audit, advertise the binding so curl-quiet still leaves a trail.
    res.setHeader('X-Tenant-Id', payload.tenantId);
    res.send(body);
  }

  /**
   * Stream the freshly-patched per-tenant binary. No temp file is written —
   * the patched bytes live only in this request's Buffer.
   */
  @Get('build')
  async buildAgent(
    @Query('token') token: string,
    @Query('os') osQ: string | undefined,
    @Query('arch') archQ: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const payload = this.installTokens.verify(token);

    const os = (osQ || '').toLowerCase() as SupportedOS;
    const arch = (archQ || '').toLowerCase() as SupportedArch;
    if (!SUPPORTED_OS.has(os)) {
      throw new BadRequestException(
        `unsupported os '${osQ}' (must be linux, darwin, or windows)`,
      );
    }
    if (!SUPPORTED_ARCH.has(arch)) {
      throw new BadRequestException(
        `unsupported arch '${archQ}' (must be amd64 or arm64)`,
      );
    }

    const publicUrl = resolvePublicUrl(req);
    const { buffer, filename } = await this.patcher.patch({
      tenantId: payload.tenantId,
      serverUrl: publicUrl,
      os,
      arch,
    });

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', String(buffer.length));
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Tenant-Id', payload.tenantId);
    res.end(buffer);
  }

  // ---------------------------------------------------------------------
  // Existing per-agent reads
  // ---------------------------------------------------------------------

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

/**
 * Determine the public URL of the API. Order (first hit wins):
 *  1. ITOM_SERVER_URL env var (project convention; set this in .env).
 *  2. ITOM_PUBLIC_URL env var (alias, kept for compatibility).
 *  3. The X-Forwarded-Proto + X-Forwarded-Host headers (behind a proxy).
 *  4. The request's protocol + host header.
 *
 * The result is the value baked into the agent's serverUrl, so it must be
 * reachable from the customer's network. Never hardcoded.
 */
function resolvePublicUrl(req: Request): string {
  const fromEnv = process.env.ITOM_SERVER_URL || process.env.ITOM_PUBLIC_URL;
  if (fromEnv) return fromEnv.replace(/\/+$/, '');

  const xfProto = (req.headers['x-forwarded-proto'] as string) || '';
  const xfHost = (req.headers['x-forwarded-host'] as string) || '';
  if (xfProto && xfHost) return `${xfProto}://${xfHost}`;

  const proto = (req.protocol || 'http').toString();
  const host = req.headers.host || 'localhost';
  return `${proto}://${host}`;
}
