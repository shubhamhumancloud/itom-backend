import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  Headers,
  Param,
  Post,
  Query,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { Response } from 'express';
import { TenantId } from '../common/decorators/tenant.decorator';
import { ScanJobService } from './scan-job.service';
import { CredentialVaultService } from './credential-vault.service';
import { CollectorService } from './collector.service';
import { SigningService } from './signing.service';
import {
  CollectorBinaryPatcherService,
  SupportedArch,
  SupportedOS,
} from './collector-binary-patcher.service';
import { DemoSeedService } from './topology/demo-seed.service';
import { ScanJobPillar } from './entities/scan-job.entity';
import { CredentialKind } from './entities/credential.entity';

interface CreateScanJobBody {
  pillar: ScanJobPillar;
  collectorId?: string | null;
  targetSpec?: Record<string, unknown>;
  credentialRefs?: string[];
}

interface CreateCredentialBody {
  name: string;
  kind: CredentialKind;
  plaintext: string;
  scopeCidrs?: string[];
  /** Optional: store the firewall host alongside the secret. */
  host?: string;
  /** Optional: pin the firewall's TLS cert SHA-256 fingerprint. */
  tlsFingerprintSha256?: string;
}

interface CreateCollectorBody {
  name: string;
  allowedCidrs?: string[];
}

/**
 * REST surface for the discovery module:
 *
 *  Operator side (tenant-scoped):
 *   - POST /v1/discovery/collectors     register a collector, get a token
 *   - GET  /v1/discovery/collectors
 *   - POST /v1/discovery/credentials    store a credential
 *   - GET  /v1/discovery/credentials
 *   - POST /v1/discovery/scans          enqueue a scan job
 *   - GET  /v1/discovery/scans
 *
 *  Collector side (collector bearer auth):
 *   - POST /v1/discovery/credentials/:id/decrypt
 *           Called by the Go collector during a scan job to fetch
 *           the plaintext secret + firewall host. Audited every call.
 *
 *  Public-ish:
 *   - GET  /v1/discovery/signing/public-key   so the installer can bake
 *           the Ed25519 public key into the collector binary.
 */
@Controller('discovery')
export class DiscoveryController {
  constructor(
    private readonly jobs: ScanJobService,
    private readonly vault: CredentialVaultService,
    private readonly collectors: CollectorService,
    private readonly signing: SigningService,
    private readonly patcher: CollectorBinaryPatcherService,
    private readonly demoSeed: DemoSeedService,
  ) {}

  // --- collectors --------------------------------------------------------

  @Post('collectors')
  async createCollector(
    @TenantId() tenantId: string | null,
    @Body() body: CreateCollectorBody,
  ) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    if (!body?.name) throw new BadRequestException('name required');
    const { collector, plaintextToken } = await this.collectors.create({
      tenantId,
      name: body.name,
      allowedCidrs: body.allowedCidrs,
    });
    // Return the plaintext token ONCE. It is not stored anywhere
    // recoverable — if the operator loses it, they rotate.
    return {
      id: collector.id,
      name: collector.name,
      tenantId: collector.tenantId,
      allowedCidrs: collector.allowedCidrs,
      bearerToken: plaintextToken,
      status: collector.status,
    };
  }

  @Get('collectors')
  async listCollectors(@TenantId() tenantId: string | null) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    const rows = await this.collectors.list(tenantId);
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      allowedCidrs: r.allowedCidrs,
      status: r.status,
      lastSeenAt: r.lastSeenAt,
      version: r.version,
      createdAt: r.createdAt,
    }));
  }

  // --- signing pubkey ----------------------------------------------------

  @Get('signing/public-key')
  signingPublicKey() {
    return {
      algorithm: 'ed25519',
      publicKeyBase64: this.signing.getPublicKeyBase64(),
    };
  }

  // --- demo data ---------------------------------------------------------

  /**
   * Plant a synthetic 6-device network for the current tenant so the
   * operator can preview the topology UI without real network gear.
   * Re-running is safe — fusion is idempotent.
   */
  @Post('demo/seed')
  async seedDemoData(@TenantId() tenantId: string | null) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    return this.demoSeed.seed(tenantId, 'dashboard');
  }

  /**
   * Wipe everything the demo seeder produced — scan jobs, sessions,
   * observations, fused devices/edges/etc. Scoped strictly to rows
   * tagged `targetSpec.demo === true`, so real discovery data is
   * never touched.
   */
  @Delete('demo/seed')
  async clearDemoData(@TenantId() tenantId: string | null) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    return this.demoSeed.clear(tenantId, 'dashboard');
  }

  // --- collector binary download ----------------------------------------

  /**
   * Stream a freshly-patched collector binary. Triggered from the
   * install one-liner the dashboard generates. The collector row must
   * exist already (POST /collectors) — its bearer is baked in here.
   *
   * Auth model: short-lived install token, the same way the agent flow
   * works. For now the endpoint also accepts the collector's existing
   * bearer for re-install/rotation use cases.
   */
  @Get('collectors/:id/install/binary')
  async downloadCollectorBinary(
    @TenantId() tenantId: string | null,
    @Param('id') collectorId: string,
    @Query('os') os: SupportedOS,
    @Query('arch') arch: SupportedArch,
    @Query('token') plaintextToken: string,
    @Res() res: Response,
  ) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    if (!os || !arch) {
      throw new BadRequestException('os and arch query params required');
    }
    if (!plaintextToken) {
      throw new BadRequestException('token query param required');
    }
    // Verify the operator still holds the token issued at create time.
    // verifyToken throws Unauthorized on mismatch.
    const collector = await this.collectors.verifyToken(
      collectorId,
      plaintextToken,
    );
    if (collector.tenantId !== tenantId) {
      throw new ForbiddenException('tenant mismatch');
    }

    const publicUrl = process.env.ITOM_PUBLIC_URL || '';
    if (!publicUrl) {
      throw new BadRequestException(
        'ITOM_PUBLIC_URL is unset — collector cannot be told where to connect',
      );
    }

    const patched = await this.patcher.patch({
      tenantId,
      serverUrl: publicUrl,
      collectorId: collector.id,
      authToken: plaintextToken,
      cidrPubKey: this.signing.getPublicKeyBase64(),
      os,
      arch,
    });
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${patched.filename}"`,
    );
    res.send(patched.buffer);
  }

  // --- scan jobs ---------------------------------------------------------

  @Post('scans')
  async createScan(@TenantId() tenantId: string | null, @Body() body: CreateScanJobBody) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    if (!body?.pillar) throw new BadRequestException('pillar is required');
    return this.jobs.create({
      tenantId,
      actor: 'dashboard',
      pillar: body.pillar,
      collectorId: body.collectorId ?? null,
      targetSpec: body.targetSpec,
      credentialRefs: body.credentialRefs,
    });
  }

  @Get('scans')
  async listScans(
    @TenantId() tenantId: string | null,
    @Query('limit') limit = '50',
  ) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    return this.jobs.list(tenantId, parseInt(limit, 10) || 50);
  }

  @Get('scans/:id')
  async getScan(@TenantId() tenantId: string | null, @Param('id') id: string) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    return this.jobs.getOne(tenantId, id);
  }

  /**
   * Chapter-0 acceptance test: run a `noop` job inline and produce one
   * observation. Confirms the data flow + tenant scoping work end-to-end
   * before any real collector code exists.
   */
  @Post('scans/:id/simulate-noop')
  async simulate(@TenantId() tenantId: string | null, @Param('id') id: string) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    return this.jobs.simulateNoop({ tenantId, actor: 'dashboard', jobId: id });
  }

  // --- credentials -------------------------------------------------------

  @Post('credentials')
  async createCredential(
    @TenantId() tenantId: string | null,
    @Body() body: CreateCredentialBody,
  ) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    if (!body?.name || !body?.kind || !body?.plaintext) {
      throw new BadRequestException('name, kind, plaintext required');
    }
    const row = await this.vault.store({
      tenantId,
      actor: 'dashboard',
      name: body.name,
      kind: body.kind,
      scopeCidrs: body.scopeCidrs,
      plaintext: body.plaintext,
      host: body.host,
      tlsFingerprintSha256: body.tlsFingerprintSha256,
    });
    // Never echo the plaintext back, and never the bytea blobs.
    return {
      id: row.id,
      name: row.name,
      kind: row.kind,
      scopeCidrs: row.scopeCidrs,
      host: row.host,
      createdAt: row.createdAt,
    };
  }

  @Get('credentials')
  async listCredentials(@TenantId() tenantId: string | null) {
    if (!tenantId) throw new UnauthorizedException('tenant context required');
    return this.vault.list(tenantId);
  }

  /**
   * Collector-only: decrypt and return the secret JIT. Authenticated
   * by the collector's bearer (not the dashboard user). The vault
   * writes one audit_log row per successful decrypt.
   *
   * Request must include:
   *   X-Tenant-Id:    tenant the credential belongs to
   *   Authorization:  Bearer <collector token>
   *
   * Response contains everything firewall.Creds needs in one round-
   * trip (host + secret + optional TLS pin), so the collector only
   * makes one call per credential per job.
   */
  @Post('credentials/:id/decrypt')
  async decryptCredential(
    @Param('id') id: string,
    @Headers('authorization') authHeader: string | undefined,
    @Headers('x-tenant-id') tenantId: string | undefined,
    @Headers('x-collector-id') collectorIdHeader: string | undefined,
  ) {
    if (!authHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Bearer token required');
    }
    if (!tenantId) throw new BadRequestException('X-Tenant-Id required');

    const token = authHeader.slice('Bearer '.length).trim();
    // Without the collector-id header we'd have to scan every collector
    // row for a hash match — possible but O(n). The collector sends it,
    // and we verify the token against that specific row.
    const collectorId = collectorIdHeader ?? '';
    if (!collectorId) {
      throw new BadRequestException('X-Collector-Id required');
    }
    const collector = await this.collectors.verifyToken(collectorId, token);
    if (collector.tenantId !== tenantId) {
      throw new ForbiddenException('tenant mismatch');
    }

    const secret = await this.vault.decryptForCollector({
      tenantId,
      collectorId: collector.id,
      credentialId: id,
    });
    return secret;
  }
}
