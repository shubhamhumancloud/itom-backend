import {
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Byte-patches a collector template binary with one tenant's identity.
 *
 * Mirrors the host-metrics agent's BinaryPatcherService pattern: read a
 * generic template from disk, find the literal placeholder strings in
 * .rodata, overwrite with the real values right-padded with NUL. The
 * collector reads each back via strings.TrimRight(s, "_\\x00").
 *
 * Why a SEPARATE service from agents/binary-patcher.service.ts:
 *   - the placeholder set differs (5 vs 2)
 *   - the template lives under a different folder (`collector-templates/`)
 *   - keeping discovery installation logic in the discovery module
 *     means a future split into a dedicated microservice is one move,
 *     not a tangled refactor
 *
 * MUST stay in sync with backend/collector/cmd/collectord/main.go.
 */

interface Placeholder {
  prefix: string;
  totalLen: number;
  envName: string;
}

const PLACEHOLDERS: Record<string, Placeholder> = {
  tenantId:    { prefix: 'ITOMBAKED_TENANT_ID:',       totalLen: 64,  envName: 'tenantId' },
  serverUrl:   { prefix: 'ITOMBAKED_SERVER_URL:',      totalLen: 256, envName: 'serverUrl' },
  collectorId: { prefix: 'ITOMBAKED_COLLECTOR_ID:',    totalLen: 64,  envName: 'collectorId' },
  authToken:   { prefix: 'ITOMBAKED_COLLECTOR_AUTH:',  totalLen: 128, envName: 'authToken' },
  cidrPubKey:  { prefix: 'ITOMBAKED_CIDR_PUBKEY:',     totalLen: 130, envName: 'cidrPubKey' },
};

export type SupportedOS = 'linux' | 'darwin' | 'windows';
export type SupportedArch = 'amd64' | 'arm64';

export interface CollectorPatchInputs {
  tenantId: string;
  serverUrl: string;
  collectorId: string;
  authToken: string;
  cidrPubKey: string; // base64-encoded Ed25519 public key
  os: SupportedOS;
  arch: SupportedArch;
}

export interface PatchedBinary {
  buffer: Buffer;
  filename: string;
}

@Injectable()
export class CollectorBinaryPatcherService {
  private readonly logger = new Logger(CollectorBinaryPatcherService.name);
  private readonly templatesDir: string;

  constructor() {
    const root =
      process.env.COLLECTOR_TEMPLATES_PATH ||
      path.join(
        process.env.AGENTS_DIST_PATH || path.join(process.cwd(), 'agents-dist'),
        'collector-templates',
      );
    this.templatesDir = path.resolve(root);
  }

  async patch(inputs: CollectorPatchInputs): Promise<PatchedBinary> {
    // Validate every value fits its slot before we read the template
    // — fails fast, no wasted disk I/O.
    const fields: Array<keyof typeof PLACEHOLDERS> = [
      'tenantId',
      'serverUrl',
      'collectorId',
      'authToken',
      'cidrPubKey',
    ];
    for (const f of fields) {
      const value = inputs[f];
      if (!value) throw new Error(`patch requires ${f}`);
      const placeholder = PLACEHOLDERS[f];
      const valBytes = Buffer.byteLength(value, 'utf8');
      if (valBytes >= placeholder.totalLen) {
        throw new Error(
          `${f} too long (${valBytes} bytes; max ${placeholder.totalLen - 1})`,
        );
      }
    }

    const filename = templateFilename(inputs.os, inputs.arch);
    const fullPath = path.join(this.templatesDir, filename);
    if (
      !fullPath.startsWith(this.templatesDir + path.sep) &&
      fullPath !== this.templatesDir
    ) {
      throw new NotFoundException('collector template not found');
    }

    let template: Buffer;
    try {
      template = await fs.readFile(fullPath);
    } catch {
      this.logger.warn(`collector template missing on disk: ${fullPath}`);
      throw new NotFoundException(
        `collector template for ${inputs.os}/${inputs.arch} not available — build collector templates and place in ${this.templatesDir}`,
      );
    }

    const out = Buffer.from(template);

    // Patch each placeholder in turn. Loop body identical for every
    // field — small placeholder map drives the work.
    for (const [field, p] of Object.entries(PLACEHOLDERS)) {
      const placeholderBytes = Buffer.from(
        p.prefix + '_'.repeat(p.totalLen - p.prefix.length),
        'ascii',
      );
      const idx = out.indexOf(placeholderBytes);
      if (idx < 0) {
        this.logger.error(
          `placeholder for ${field} not found in ${filename} — was the template built from the current collector source?`,
        );
        throw new InternalServerErrorException(
          `collector template missing ${field} placeholder; rebuild templates`,
        );
      }
      writeRegion(out, idx, p.totalLen, (inputs as any)[field]);
    }

    return {
      buffer: out,
      filename: downloadFilename(inputs.os, inputs.arch),
    };
  }
}

function templateFilename(os: SupportedOS, arch: SupportedArch): string {
  if (os === 'windows') return `itom-collector-windows-${arch}.exe`;
  return `itom-collector-${os}-${arch}`;
}

function downloadFilename(os: SupportedOS, arch: SupportedArch): string {
  return templateFilename(os, arch);
}

function writeRegion(buf: Buffer, start: number, length: number, value: string): void {
  buf.fill(0, start, start + length);
  buf.write(value, start, length, 'utf8');
}
