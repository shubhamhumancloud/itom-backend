import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, ILike } from 'typeorm';
import { Site } from '../entities/site.entity';
import { Device } from '../entities/device.entity';
import { NetworkInterface } from '../entities/network-interface.entity';
import { IpBinding } from '../entities/ip-binding.entity';
import { NeighborEdge } from '../entities/neighbor-edge.entity';
import { OpenPort } from '../entities/open-port.entity';
import { DiscoveryEvent } from '../entities/discovery-event.entity';
import { DiscoverySession } from '../entities/discovery-session.entity';
import { Observation } from '../entities/observation.entity';

/**
 * Read-only API the dashboard hits. Pure SELECTs over the typed
 * tables fusion produced. Output of `topology()` is Cytoscape.js-
 * shaped JSON so the frontend can hand it straight to the renderer.
 */
@Injectable()
export class TopologyService {
  constructor(
    @InjectRepository(Site) private readonly sites: Repository<Site>,
    @InjectRepository(Device) private readonly devices: Repository<Device>,
    @InjectRepository(NetworkInterface)
    private readonly interfaces: Repository<NetworkInterface>,
    @InjectRepository(IpBinding) private readonly ipBindings: Repository<IpBinding>,
    @InjectRepository(NeighborEdge) private readonly edges: Repository<NeighborEdge>,
    @InjectRepository(OpenPort) private readonly openPorts: Repository<OpenPort>,
    @InjectRepository(DiscoveryEvent) private readonly events: Repository<DiscoveryEvent>,
    @InjectRepository(DiscoverySession)
    private readonly sessions: Repository<DiscoverySession>,
    @InjectRepository(Observation)
    private readonly observations: Repository<Observation>,
  ) {}

  async listSites(tenantId: string) {
    return this.sites.find({
      where: { tenantId },
      order: { name: 'ASC' },
    });
  }

  /**
   * Cytoscape-formatted topology. nodes/edges arrays of
   * { data: {...} } objects, ready to feed `cy.add()`.
   *
   * If siteId is omitted, every device for the tenant is included.
   */
  async topology(tenantId: string, siteId?: string) {
    const where: any = { tenantId };
    if (siteId) where.siteId = siteId;

    const devices = await this.devices.find({ where, order: { hostname: 'ASC' } });
    if (devices.length === 0) {
      return { nodes: [], edges: [] };
    }
    const deviceIds = devices.map((d) => d.id);
    const edges = await this.edges.find({
      where: { tenantId, fromDeviceId: In(deviceIds) },
    });

    const nodes = devices.map((d) => ({
      data: {
        id: d.id,
        label: d.hostname || d.managementIp || d.identityKey,
        kind: d.kind,
        vendor: d.vendor,
        model: d.model,
        identityKey: d.identityKey,
        managementIp: d.managementIp,
        availability: d.availabilityState,
        lifecycle: d.lifecycleState,
        lastSeenAt: d.lastSeenAt,
        sources: d.sources,
      },
    }));

    const edgesOut = edges.map((e) => ({
      data: {
        id: e.id,
        source: e.fromDeviceId,
        target: e.toDeviceId,
        kind: e.kind,
        fromIfIndex: e.fromIfIndex,
        toIfIndex: e.toIfIndex,
        lastSeenAt: e.lastSeenAt,
      },
    }));

    return { nodes, edges: edgesOut };
  }

  /**
   * Flat host list — Advanced-IP-Scanner-style row per device:
   *   { status, hostname, ip, mac, vendor, ports, lastSeenAt, ... }
   *
   * Powers the `/discovery/hosts` page. We fan out one extra query for
   * interfaces, ip bindings, and open ports, then stitch in memory.
   * For up to a few thousand devices this is faster + simpler than a
   * multi-join — TypeORM's eager-join machinery generates wide rows
   * that we'd post-process anyway.
   *
   * Optional `collectorId` filter: only return devices whose
   * observations were produced by that collector. Implemented by
   * walking sessions → observation subject_keys → device identity_keys.
   * This is the right filter for "what did THIS collector find on its
   * last scan?" — independent of any other collector's seed data.
   */
  async listHosts(
    tenantId: string,
    opts: { search?: string; limit?: number; collectorId?: string } = {},
  ) {
    const limit = opts.limit ?? 500;

    let identityKeyFilter: string[] | null = null;
    if (opts.collectorId) {
      const sessions = await this.sessions.find({
        where: { tenantId, collectorId: opts.collectorId },
        select: ['id'],
      });
      if (sessions.length === 0) return [];
      const sessionIds = sessions.map((s) => s.id);
      const obs = await this.observations.find({
        where: { sessionId: In(sessionIds), subjectKind: 'device' },
        select: ['subjectKey'],
      });
      identityKeyFilter = Array.from(
        new Set(obs.map((o) => o.subjectKey).filter(Boolean)),
      );
      if (identityKeyFilter.length === 0) return [];
    }

    const where: any = { tenantId };
    if (opts.search && opts.search.trim()) {
      where.hostname = ILike(`%${opts.search.trim()}%`);
    }
    if (identityKeyFilter) {
      where.identityKey = In(identityKeyFilter);
    }
    const devices = await this.devices.find({
      where,
      order: { lastSeenAt: 'DESC' },
      take: limit,
    });
    if (devices.length === 0) return [];
    const deviceIds = devices.map((d) => d.id);

    const [interfaces, ips, ports] = await Promise.all([
      this.interfaces.find({
        where: { tenantId, deviceId: In(deviceIds) },
        order: { ifIndex: 'ASC' },
      }),
      this.ipBindings.find({
        where: { tenantId, deviceId: In(deviceIds) },
      }),
      this.openPorts.find({
        where: { tenantId, deviceId: In(deviceIds) },
        order: { port: 'ASC' },
      }),
    ]);

    // Index by deviceId once, lookups are O(1).
    const ifsByDev = new Map<string, typeof interfaces>();
    const ipsByDev = new Map<string, typeof ips>();
    const portsByDev = new Map<string, typeof ports>();
    for (const i of interfaces) {
      const arr = ifsByDev.get(i.deviceId) ?? [];
      arr.push(i);
      ifsByDev.set(i.deviceId, arr);
    }
    for (const ip of ips) {
      const arr = ipsByDev.get(ip.deviceId) ?? [];
      arr.push(ip);
      ipsByDev.set(ip.deviceId, arr);
    }
    for (const p of ports) {
      const arr = portsByDev.get(p.deviceId) ?? [];
      arr.push(p);
      portsByDev.set(p.deviceId, arr);
    }

    return devices.map((d) => {
      const devIfaces = ifsByDev.get(d.id) ?? [];
      const devIps = ipsByDev.get(d.id) ?? [];
      const devPorts = portsByDev.get(d.id) ?? [];
      // First non-empty MAC across interfaces. For workstations
      // discovered only by active-scan there are usually no MACs
      // (no SNMP / ARP source); the column renders as "—" in that case.
      const mac = devIfaces.map((i) => i.mac).find(Boolean) ?? null;
      const allIps = Array.from(
        new Set([
          ...(d.managementIp ? [d.managementIp] : []),
          ...devIps.map((b) => b.ip),
        ]),
      );
      return {
        id: d.id,
        hostname: d.hostname,
        ip: d.managementIp ?? devIps[0]?.ip ?? null,
        ips: allIps,
        mac,
        vendor: d.vendor,
        model: d.model,
        kind: d.kind,
        availability: d.availabilityState,
        lifecycle: d.lifecycleState,
        identityKey: d.identityKey,
        sysDescr: d.sysDescr,
        lastSeenAt: d.lastSeenAt,
        sources: d.sources,
        ports: devPorts.map((p) => ({
          port: p.port,
          protocol: p.protocol,
          service: p.service,
          banner: p.banner,
          tlsCertCn: p.tlsCertCn,
        })),
      };
    });
  }

  async listDevices(tenantId: string, search?: string, limit = 100) {
    const where: any = { tenantId };
    if (search && search.trim()) {
      where.hostname = ILike(`%${search.trim()}%`);
    }
    const rows = await this.devices.find({
      where,
      order: { lastSeenAt: 'DESC' },
      take: limit,
    });
    return rows;
  }

  /**
   * Full device detail: device row + its interfaces + IPs + open
   * ports + the last 50 events touching it. One round-trip to the
   * API powers the click-to-detail panel on the topology page.
   */
  async deviceDetail(tenantId: string, id: string) {
    const device = await this.devices.findOneBy({ id, tenantId });
    if (!device) throw new NotFoundException('device not found');
    const [interfaces, ips, ports, events, neighborsIn, neighborsOut] = await Promise.all([
      this.interfaces.find({
        where: { deviceId: id, tenantId },
        order: { ifIndex: 'ASC' },
      }),
      this.ipBindings.find({ where: { deviceId: id, tenantId } }),
      this.openPorts.find({
        where: { deviceId: id, tenantId },
        order: { port: 'ASC' },
      }),
      this.events.find({
        where: { deviceId: id, tenantId },
        order: { createdAt: 'DESC' },
        take: 50,
      }),
      this.edges.find({ where: { toDeviceId: id, tenantId } }),
      this.edges.find({ where: { fromDeviceId: id, tenantId } }),
    ]);
    return {
      device,
      interfaces,
      ips,
      openPorts: ports,
      events,
      neighbors: {
        incoming: neighborsIn,
        outgoing: neighborsOut,
      },
    };
  }
}
