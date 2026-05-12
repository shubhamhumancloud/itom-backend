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
