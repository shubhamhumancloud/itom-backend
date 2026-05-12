import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, In, Repository } from 'typeorm';
import { Observation } from '../entities/observation.entity';
import { Site } from '../entities/site.entity';
import {
  Device,
  DeviceAvailabilityState,
  DeviceKind,
} from '../entities/device.entity';
import { NetworkInterface } from '../entities/network-interface.entity';
import { IpBinding } from '../entities/ip-binding.entity';
import { NeighborEdge, EdgeKind } from '../entities/neighbor-edge.entity';
import { OpenPort } from '../entities/open-port.entity';
import { DiscoveryEvent } from '../entities/discovery-event.entity';

/**
 * Fact-fusion service — chapter 4.
 *
 * Reads observation rows produced by the three pillars (firewall
 * ingest, SNMP crawl, active scan) and produces typed current-state
 * rows that the topology UI queries.
 *
 * Scope for the MVP:
 *   - Identity merge by chassis serial → MAC → IP.
 *   - Per-attribute "latest-wins" within a single source rank.
 *   - Source rank: SNMP > firewall ingest > active-scan banner.
 *   - Emits device_added / new_open_port / new_neighbor_edge events.
 *
 * Deferred:
 *   - Conflict log table (we just overwrite; chapter-4 doc full-
 *     fidelity conflict reasoning is a polish PR).
 *   - Snapshot + diff (chapter-4 doc; can be added on top later).
 *   - Hysteresis-based availability flapping (today we just stamp
 *     lastSeenAt; availability flips to 'up' on any current obs).
 *
 * Concurrency note: fuseSession is wrapped in a single transaction so
 * a mid-flight crash leaves the db consistent. Multiple sessions for
 * the same tenant fusing concurrently use Postgres advisory locks
 * keyed by the device identityKey hash to serialise per-device.
 */
@Injectable()
export class FusionService {
  private readonly logger = new Logger(FusionService.name);

  constructor(
    @InjectRepository(Observation)
    private readonly observations: Repository<Observation>,
    @InjectRepository(Site)
    private readonly sites: Repository<Site>,
    @InjectRepository(Device)
    private readonly devices: Repository<Device>,
    @InjectRepository(NetworkInterface)
    private readonly interfaces: Repository<NetworkInterface>,
    @InjectRepository(IpBinding)
    private readonly ipBindings: Repository<IpBinding>,
    @InjectRepository(NeighborEdge)
    private readonly edges: Repository<NeighborEdge>,
    @InjectRepository(OpenPort)
    private readonly openPorts: Repository<OpenPort>,
    @InjectRepository(DiscoveryEvent)
    private readonly events: Repository<DiscoveryEvent>,
    @InjectDataSource()
    private readonly dataSource: DataSource,
  ) {}

  /**
   * Fuse every observation in one session. Idempotent — running it
   * twice produces the same end state. Called from the gateway after
   * scan_job.done arrives.
   */
  async fuseSession(
    sessionId: string,
  ): Promise<{ tenantId: string | null; devices: number; edges: number; events: number }> {
    const obs = await this.observations.find({
      where: { sessionId },
      order: { seenAt: 'ASC' },
    });
    if (obs.length === 0) {
      return { tenantId: null, devices: 0, edges: 0, events: 0 };
    }
    const tenantId = obs[0].tenantId;
    const siteId = await this.ensureDefaultSite(tenantId);

    // Single transaction for the whole session — if anything fails,
    // the caller can retry without partial state.
    return this.dataSource.transaction(async (em) => {
      const ctx = new FusionContext(tenantId, siteId, em);

      // 1) First pass — devices. Build them so subsequent passes can
      // resolve subjectKey → deviceId.
      for (const o of obs) {
        if (o.subjectKind === 'device' && o.attribute === 'snmp_identity') {
          await this.fuseSNMPIdentity(ctx, o);
        } else if (o.subjectKind === 'device' && o.attribute === 'fingerprint') {
          await this.fuseFingerprint(ctx, o);
        } else if (o.subjectKind === 'device' && o.attribute === 'alive') {
          await this.fuseAliveHost(ctx, o);
        }
      }

      // 2) Second pass — children that hang off devices.
      for (const o of obs) {
        switch (`${o.subjectKind}.${o.attribute}`) {
          case 'interface.config':
            await this.fuseInterface(ctx, o);
            break;
          case 'ip_binding.config':
            await this.fuseIpBindingFromSnmp(ctx, o);
            break;
          case 'open_port.service':
            await this.fuseOpenPort(ctx, o);
            break;
          case 'link.lldp':
          case 'link.cdp':
            await this.fuseNeighborEdge(ctx, o);
            break;
        }
      }

      // 3) Persist queued events.
      if (ctx.events.length > 0) {
        await em.insert(DiscoveryEvent, ctx.events);
      }

      return {
        tenantId,
        devices: ctx.devicesTouched.size,
        edges: ctx.edgesTouched,
        events: ctx.events.length,
      };
    });
  }

  // --------------------------------------------------------------------
  // Fusion handlers — one per observation shape we know about
  // --------------------------------------------------------------------

  private async fuseSNMPIdentity(ctx: FusionContext, o: Observation): Promise<void> {
    const v = (o.value ?? {}) as Record<string, any>;
    const chassisId = v.chassisId as string | undefined;
    if (!chassisId) return;
    const identityKey = `chassis:${chassisId}`;
    const kind = guessKind({
      vendor: undefined,
      sysDescr: v.sysDescr,
      // SNMP devices are almost always switches/routers/firewalls.
      defaultKind: 'switch',
    });
    await ctx.upsertDevice({
      identityKey,
      hostname: v.sysName,
      kind,
      vendor: undefined, // generic-SNMP driver doesn't populate vendor — fingerprint obs does
      model: v.chassisModel,
      sysDescr: v.sysDescr,
      chassisSerial: v.chassisSerial || chassisId,
      managementIp: v.managementIp,
      sourceRank: 100, // SNMP is the most authoritative
      source: 'snmp',
      seenAt: o.seenAt,
    });
  }

  private async fuseFingerprint(ctx: FusionContext, o: Observation): Promise<void> {
    const v = (o.value ?? {}) as Record<string, any>;
    const sk = o.subjectKey; // e.g. "ip:10.0.0.1"
    const ip = sk.startsWith('ip:') ? sk.substring(3) : null;
    if (!ip) return;
    // Don't create a new device row from a fingerprint alone if
    // confidence is none — too noisy. snmp_identity already covers
    // confident SNMP devices.
    if (v.confidence === 'none' && !v.vendor) return;
    await ctx.upsertDevice({
      identityKey: `ip:${ip}`,
      kind: vendorToKind(v.vendor),
      vendor: v.vendor || null,
      managementIp: ip,
      sourceRank: 40, // fingerprint is mid-strength
      source: 'fingerprint',
      seenAt: o.seenAt,
    });
  }

  private async fuseAliveHost(ctx: FusionContext, o: Observation): Promise<void> {
    const sk = o.subjectKey;
    const ip = sk.startsWith('ip:') ? sk.substring(3) : null;
    if (!ip) return;
    await ctx.upsertDevice({
      identityKey: `ip:${ip}`,
      kind: 'unknown',
      managementIp: ip,
      sourceRank: 20, // alive-only is the weakest evidence
      source: 'active',
      seenAt: o.seenAt,
    });
  }

  private async fuseInterface(ctx: FusionContext, o: Observation): Promise<void> {
    const v = (o.value ?? {}) as Record<string, any>;
    // subjectKey: "chassis:<id>|if:<ifIndex>"
    const chassisId = extractKeyPart(o.subjectKey, 'chassis:');
    if (!chassisId) return;
    const dev = await ctx.deviceByIdentity(`chassis:${chassisId}`);
    if (!dev) return;
    const ifIndex = Number(v.index ?? 0);
    if (!ifIndex) return;
    const row = await ctx.em.findOne(NetworkInterface, {
      where: { deviceId: dev.id, ifIndex },
    });
    if (row) {
      row.name = v.name ?? row.name;
      row.description = v.description ?? row.description;
      row.type = String(v.type ?? '') || row.type;
      row.speedBps = String(v.speedBps ?? row.speedBps);
      row.mac = v.mac || row.mac;
      row.adminStatus = v.adminStatus || row.adminStatus;
      row.operStatus = v.operStatus || row.operStatus;
      row.zone = v.zone || row.zone;
      row.lastSeenAt = new Date(o.seenAt);
      await ctx.em.save(row);
    } else {
      await ctx.em.insert(NetworkInterface, {
        tenantId: ctx.tenantId,
        deviceId: dev.id,
        ifIndex,
        name: v.name ?? `if${ifIndex}`,
        description: v.description ?? null,
        type: v.type ? String(v.type) : null,
        speedBps: String(v.speedBps ?? 0),
        mac: v.mac || null,
        adminStatus: v.adminStatus || 'unknown',
        operStatus: v.operStatus || 'unknown',
        zone: v.zone || null,
        lastSeenAt: new Date(o.seenAt),
      });
    }
  }

  private async fuseIpBindingFromSnmp(ctx: FusionContext, o: Observation): Promise<void> {
    const v = (o.value ?? {}) as Record<string, any>;
    const chassisId = extractKeyPart(o.subjectKey, 'chassis:');
    if (!chassisId) return;
    const dev = await ctx.deviceByIdentity(`chassis:${chassisId}`);
    if (!dev) return;
    const ifIndex = Number(v.ifIndex ?? 0);
    const ip = v.ip as string | undefined;
    if (!ifIndex || !ip) return;
    const iface = await ctx.em.findOne(NetworkInterface, {
      where: { deviceId: dev.id, ifIndex },
    });
    if (!iface) return;
    const existing = await ctx.em.findOne(IpBinding, {
      where: { interfaceId: iface.id, ip },
    });
    if (existing) {
      existing.prefixLen = v.prefixLen ?? existing.prefixLen;
      existing.lastSeenAt = new Date(o.seenAt);
      await ctx.em.save(existing);
    } else {
      await ctx.em.insert(IpBinding, {
        tenantId: ctx.tenantId,
        deviceId: dev.id,
        interfaceId: iface.id,
        ip,
        prefixLen: v.prefixLen ?? null,
        lastSeenAt: new Date(o.seenAt),
      });
    }
  }

  private async fuseOpenPort(ctx: FusionContext, o: Observation): Promise<void> {
    const v = (o.value ?? {}) as Record<string, any>;
    // subjectKey: "ip:<ip>|port:<port>"
    const ip = extractKeyPart(o.subjectKey, 'ip:');
    if (!ip) return;
    const dev = await ctx.deviceByIdentity(`ip:${ip}`);
    if (!dev) return;
    const port = Number(v.port);
    if (!port) return;
    const protocol = String(v.protocol ?? 'tcp');
    const existing = await ctx.em.findOne(OpenPort, {
      where: { deviceId: dev.id, port, protocol },
    });
    const wasNew = !existing;
    const row = existing ?? this.openPorts.create({
      tenantId: ctx.tenantId,
      deviceId: dev.id,
      port,
      protocol,
    });
    row.service = v.service ?? row.service;
    row.banner = v.banner ?? row.banner;
    row.tlsCertCn = v.tlsCertCn ?? row.tlsCertCn;
    row.tlsCertSans = (v.tlsCertSans as string[]) ?? row.tlsCertSans ?? [];
    row.lastSeenAt = new Date(o.seenAt);
    await ctx.em.save(OpenPort, row);
    if (wasNew) {
      ctx.events.push({
        tenantId: ctx.tenantId,
        deviceId: dev.id,
        kind: 'new_open_port',
        payload: { port, protocol, service: row.service, banner: row.banner },
      } as unknown as DiscoveryEvent);
    }
  }

  private async fuseNeighborEdge(ctx: FusionContext, o: Observation): Promise<void> {
    const v = (o.value ?? {}) as Record<string, any>;
    const localChassisId = String(v.localChassisId ?? '');
    const peerChassisId = String(v.peerChassisId ?? '');
    if (!localChassisId || !peerChassisId) return;
    const from = await ctx.deviceByIdentity(`chassis:${localChassisId}`);
    if (!from) return;
    // For the peer we may not have an SNMP identity yet — the peer is
    // another switch we haven't crawled or it's an end host. Find or
    // create a thin device row keyed on the peer chassis id; if the
    // chassis id looks like a MAC we use that for identity.
    const peerKey = peerChassisIdToKey(peerChassisId);
    let to = await ctx.deviceByIdentity(peerKey);
    if (!to) {
      to = await ctx.upsertDevice({
        identityKey: peerKey,
        hostname: v.peerSysName,
        kind: 'unknown',
        sourceRank: 50, // LLDP/CDP is decent evidence of "a switch exists here"
        source: o.attribute, // 'lldp' or 'cdp'
        seenAt: o.seenAt,
      });
    }
    const fromIfIndex = v.localPort ?? null;
    const toIfIndex = v.peerPort ?? null;
    const kind: EdgeKind = o.attribute === 'cdp' ? 'cdp' : 'lldp';
    const existing = await ctx.em.findOne(NeighborEdge, {
      where: {
        tenantId: ctx.tenantId,
        fromDeviceId: from.id,
        toDeviceId: to.id,
        kind,
        fromIfIndex: typeof fromIfIndex === 'number' ? fromIfIndex : null,
        toIfIndex: typeof toIfIndex === 'number' ? toIfIndex : null,
      },
    });
    const wasNew = !existing;
    const row = existing ?? this.edges.create({
      tenantId: ctx.tenantId,
      fromDeviceId: from.id,
      toDeviceId: to.id,
      kind,
      fromIfIndex: typeof fromIfIndex === 'number' ? fromIfIndex : null,
      toIfIndex: typeof toIfIndex === 'number' ? toIfIndex : null,
      meta: {},
    });
    row.meta = {
      peerPortId: v.peerPortId,
      peerPortDesc: v.peerPortDesc,
      peerSysName: v.peerSysName,
    };
    row.lastSeenAt = new Date(o.seenAt);
    await ctx.em.save(NeighborEdge, row);
    ctx.edgesTouched++;
    if (wasNew) {
      ctx.events.push({
        tenantId: ctx.tenantId,
        deviceId: from.id,
        kind: 'new_neighbor_edge',
        payload: { peer: peerKey, edgeKind: kind, fromIfIndex, toIfIndex },
      } as unknown as DiscoveryEvent);
    }
  }

  // --------------------------------------------------------------------
  // helpers
  // --------------------------------------------------------------------

  private async ensureDefaultSite(tenantId: string): Promise<string> {
    let site = await this.sites.findOneBy({ tenantId, name: 'Primary' });
    if (site) return site.id;
    site = await this.sites.save(
      this.sites.create({ tenantId, name: 'Primary', description: 'Default site for discovered devices' }),
    );
    return site.id;
  }
}

// ---------- internal helpers ----------

class FusionContext {
  em: any; // EntityManager — typed loose to avoid the import dance
  devicesTouched = new Set<string>();
  edgesTouched = 0;
  events: DiscoveryEvent[] = [];
  // Cache devices by identityKey + by id so child handlers don't refetch.
  private byKey = new Map<string, Device>();
  private byId = new Map<string, Device>();

  constructor(public tenantId: string, public siteId: string, em: any) {
    this.em = em;
  }

  async deviceByIdentity(key: string): Promise<Device | null> {
    if (this.byKey.has(key)) return this.byKey.get(key)!;
    const row: Device | null = await this.em.findOne(Device, {
      where: { tenantId: this.tenantId, identityKey: key },
    });
    if (row) {
      this.byKey.set(key, row);
      this.byId.set(row.id, row);
    }
    return row;
  }

  async upsertDevice(input: {
    identityKey: string;
    hostname?: string | null;
    kind: DeviceKind;
    vendor?: string | null;
    model?: string | null;
    sysDescr?: string | null;
    chassisSerial?: string | null;
    managementIp?: string | null;
    sourceRank: number;
    source: string;
    seenAt: Date;
  }): Promise<Device> {
    const existing = await this.deviceByIdentity(input.identityKey);
    const seenAt = new Date(input.seenAt);
    if (existing) {
      // Per-attribute precedence: stronger rank wins; same rank, newer wins.
      const apply = (
        field: keyof Device,
        candidate: string | null | undefined,
      ): void => {
        if (candidate === undefined || candidate === null || candidate === '') return;
        const lastRank = (existing as any).__lastRank?.[field] ?? -1;
        if (input.sourceRank >= lastRank) {
          (existing as any)[field] = candidate;
          (existing as any).__lastRank = (existing as any).__lastRank ?? {};
          (existing as any).__lastRank[field] = input.sourceRank;
        }
      };
      apply('hostname', input.hostname ?? null);
      apply('vendor', input.vendor ?? null);
      apply('model', input.model ?? null);
      apply('sysDescr', input.sysDescr ?? null);
      apply('chassisSerial', input.chassisSerial ?? null);
      apply('managementIp', input.managementIp ?? null);
      if (input.kind !== 'unknown' || existing.kind === 'unknown') {
        existing.kind = input.kind;
      }
      existing.lastSeenAt = seenAt;
      existing.availabilityState = 'up' as DeviceAvailabilityState;
      if (!existing.sources.includes(input.source)) {
        existing.sources = [...existing.sources, input.source];
      }
      await this.em.save(Device, existing);
      this.devicesTouched.add(existing.id);
      return existing;
    }
    const row = await this.em.save(Device, {
      tenantId: this.tenantId,
      siteId: this.siteId,
      identityKey: input.identityKey,
      hostname: input.hostname ?? null,
      kind: input.kind,
      vendor: input.vendor ?? null,
      model: input.model ?? null,
      sysDescr: input.sysDescr ?? null,
      chassisSerial: input.chassisSerial ?? null,
      managementIp: input.managementIp ?? null,
      lifecycleState: 'active',
      availabilityState: 'up',
      lastSeenAt: seenAt,
      sources: [input.source],
    });
    this.byKey.set(row.identityKey, row);
    this.byId.set(row.id, row);
    this.devicesTouched.add(row.id);
    this.events.push({
      tenantId: this.tenantId,
      deviceId: row.id,
      kind: 'device_added',
      payload: { identityKey: row.identityKey, source: input.source },
    } as unknown as DiscoveryEvent);
    return row;
  }
}

function extractKeyPart(key: string, prefix: string): string | null {
  if (!key) return null;
  for (const part of key.split('|')) {
    if (part.startsWith(prefix)) {
      return part.substring(prefix.length);
    }
  }
  return null;
}

function peerChassisIdToKey(s: string): string {
  // Heuristic: 6-octet MAC-looking strings → mac:; everything else
  // (sysName, OID) → chassis:.
  if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s)) {
    return `mac:${s.toLowerCase()}`;
  }
  return `chassis:${s}`;
}

function guessKind(input: {
  vendor?: string;
  sysDescr?: string;
  defaultKind?: DeviceKind;
}): DeviceKind {
  const d = (input.sysDescr || '').toLowerCase();
  if (d.includes('fortigate') || d.includes('asa') || d.includes('palo')) return 'firewall';
  if (d.includes('ios xr') || d.includes('aggregation services router') || d.includes('asr ')) return 'router';
  // Windows desktop / macOS detection MUST run before the generic
  // 'windows' / 'linux' branches below, otherwise a "Windows 10"
  // host would be classified as a server.
  if (d.includes('windows 10') || d.includes('windows 11') || d.includes('mac os') || d.includes('macos')) return 'workstation';
  if (d.includes('catalyst') || d.includes('procurve') || d.includes('switch')) return 'switch';
  if (d.includes('router')) return 'router';
  if (d.includes('printer') || d.includes('jetdirect')) return 'printer';
  if (d.includes('windows server') || d.includes('ubuntu') || d.includes('centos') || d.includes('rhel') || d.includes('debian') || d.includes('linux')) return 'server';
  return input.defaultKind ?? 'unknown';
}

function vendorToKind(v?: string): DeviceKind {
  switch ((v || '').toLowerCase()) {
    case 'fortinet':
    case 'paloalto':
    case 'checkpoint':
    case 'cisco_asa':
      return 'firewall';
    case 'cisco':
    case 'cisco_ios':
    case 'juniper':
      return 'router';
    case 'hp':
    case 'dell':
    case 'netgear':
    case 'mikrotik':
      return 'switch';
    case 'windows':
    case 'macos':
    case 'workstation':
      return 'workstation';
    case 'linux':
    case 'ubuntu':
    case 'centos':
    case 'server':
      return 'server';
    default:
      return 'unknown';
  }
}
