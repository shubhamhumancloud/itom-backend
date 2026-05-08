import {
  Injectable,
  Logger,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Reads an agent template binary from disk, finds the literal placeholder
 * byte regions for tenantId and serverUrl, and overwrites them with this
 * tenant's specific values right-padded with NUL.
 *
 * The agent reads back the patched values via strings.TrimRight(s, "_\x00")
 * — that's why we use NUL padding (not underscores) for the trailing bytes
 * so the agent never sees stray pad characters.
 *
 * This service does not cache patched binaries. Each request reads the
 * template fresh, patches in memory, and returns a Buffer that is streamed
 * and then garbage-collected. No tenant-specific bytes ever touch the BE
 * filesystem.
 *
 * The template file on disk is generic and shared — it contains the literal
 * placeholder strings, not any tenant data.
 */

// MUST stay in sync with backend/agent/cmd/agentd/main.go.
const TENANT_PREFIX = 'ITOMBAKED_TENANT_ID:';
const SERVER_URL_PREFIX = 'ITOMBAKED_SERVER_URL:';
const TENANT_REGION_LEN = 64;
const SERVER_URL_REGION_LEN = 256;

// Full placeholder strings (prefix + underscore padding). Searching for the
// FULL placeholder excludes the bare-prefix const that the agent's source
// code also references — those are 20/21 bytes; the var slot is 64/256.
const TENANT_PLACEHOLDER = Buffer.from(
  TENANT_PREFIX + '_'.repeat(TENANT_REGION_LEN - TENANT_PREFIX.length),
  'ascii',
);
const SERVER_URL_PLACEHOLDER = Buffer.from(
  SERVER_URL_PREFIX +
    '_'.repeat(SERVER_URL_REGION_LEN - SERVER_URL_PREFIX.length),
  'ascii',
);

export type SupportedOS = 'linux' | 'darwin' | 'windows';
export type SupportedArch = 'amd64' | 'arm64';

export interface PatchInputs {
  tenantId: string;
  serverUrl: string;
  os: SupportedOS;
  arch: SupportedArch;
}

export interface PatchedBinary {
  buffer: Buffer;
  filename: string;
}

@Injectable()
export class BinaryPatcherService {
  private readonly logger = new Logger(BinaryPatcherService.name);

  // Where templates live on disk. CI / `make build-all` writes here.
  private readonly templatesDir: string;

  constructor() {
    const root = process.env.AGENT_TEMPLATES_PATH || path.join(
      process.env.AGENTS_DIST_PATH || path.join(process.cwd(), 'agents-dist'),
      'templates',
    );
    this.templatesDir = path.resolve(root);
  }

  async patch(inputs: PatchInputs): Promise<PatchedBinary> {
    const { tenantId, serverUrl, os, arch } = inputs;

    if (!tenantId) throw new Error('patch requires tenantId');
    if (!serverUrl) throw new Error('patch requires serverUrl');

    const tenantBytes = Buffer.byteLength(tenantId, 'utf8');
    if (tenantBytes >= TENANT_REGION_LEN) {
      throw new Error(
        `tenantId too long (${tenantBytes} bytes; max ${TENANT_REGION_LEN - 1})`,
      );
    }
    const serverUrlBytes = Buffer.byteLength(serverUrl, 'utf8');
    if (serverUrlBytes >= SERVER_URL_REGION_LEN) {
      throw new Error(
        `serverUrl too long (${serverUrlBytes} bytes; max ${SERVER_URL_REGION_LEN - 1})`,
      );
    }

    const filename = templateFilename(os, arch);
    const fullPath = path.join(this.templatesDir, filename);

    // Path traversal hardening — fullPath must remain under templatesDir.
    if (
      !fullPath.startsWith(this.templatesDir + path.sep) &&
      fullPath !== this.templatesDir
    ) {
      throw new NotFoundException('template not found');
    }

    let template: Buffer;
    try {
      template = await fs.readFile(fullPath);
    } catch (err) {
      this.logger.warn(`template missing on disk: ${fullPath}`);
      throw new NotFoundException(
        `agent template for ${os}/${arch} is not available — run 'make build-all' on the backend host to publish templates`,
      );
    }

    // Buffer.from(template) deep-copies so the cached fs read isn't mutated
    // by our patch (Node's fs.readFile already returns a fresh Buffer per
    // call, but an explicit copy makes the no-shared-state contract loud).
    const out = Buffer.from(template);

    const tenantIdx = out.indexOf(TENANT_PLACEHOLDER);
    if (tenantIdx < 0) {
      this.logger.error(
        `tenant placeholder not found in template ${filename} — was the template built from the current agent source?`,
      );
      throw new InternalServerErrorException(
        'agent template is missing the tenant placeholder; rebuild templates',
      );
    }
    writePlaceholderRegion(out, tenantIdx, TENANT_REGION_LEN, tenantId);

    const urlIdx = out.indexOf(SERVER_URL_PLACEHOLDER);
    if (urlIdx < 0) {
      this.logger.error(
        `server-url placeholder not found in template ${filename}`,
      );
      throw new InternalServerErrorException(
        'agent template is missing the server-url placeholder; rebuild templates',
      );
    }
    writePlaceholderRegion(out, urlIdx, SERVER_URL_REGION_LEN, serverUrl);

    return {
      buffer: out,
      filename: downloadFilename(os, arch),
    };
  }
}

function templateFilename(os: SupportedOS, arch: SupportedArch): string {
  if (os === 'windows') return `itom-agent-windows-${arch}.exe`;
  return `itom-agent-${os}-${arch}`;
}

function downloadFilename(os: SupportedOS, arch: SupportedArch): string {
  // Match the template filename for now — keeps OS detection trivial in the
  // install scripts. Could be customised later (e.g. per-tenant prefix).
  return templateFilename(os, arch);
}

function writePlaceholderRegion(
  buf: Buffer,
  start: number,
  length: number,
  value: string,
): void {
  buf.fill(0, start, start + length);
  buf.write(value, start, length, 'utf8');
}
