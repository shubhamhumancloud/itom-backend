import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { v4 as uuid } from 'uuid';
import { Observation } from '../entities/observation.entity';
import { DiscoverySession } from '../entities/discovery-session.entity';
import { ScanJob, ScanJobStatus } from '../entities/scan-job.entity';
import { Device } from '../entities/device.entity';
import { NetworkInterface } from '../entities/network-interface.entity';
import { IpBinding } from '../entities/ip-binding.entity';
import { NeighborEdge } from '../entities/neighbor-edge.entity';
import { OpenPort } from '../entities/open-port.entity';
import { DiscoveryEvent } from '../entities/discovery-event.entity';
import { FusionService } from '../fusion/fusion.service';

/**
 * Demo data generator — lets an operator preview the topology page
 * without standing up real network gear. Plants a 19-device enterprise
 * reference topology (dual-ISP edge + perimeter ASAs + DC routers +
 * campus cores/distribution/access + DMZ ASA/server + 4 PCs) as
 * observations, then fuses them so the typed tables populate.
 *
 * Designed for dev / sandbox tenants. Production deployments can
 * disable the endpoint behind feature flag.
 */
@Injectable()
export class DemoSeedService {
  private readonly logger = new Logger(DemoSeedService.name);

  constructor(
    @InjectRepository(Observation)
    private readonly observations: Repository<Observation>,
    @InjectRepository(DiscoverySession)
    private readonly sessions: Repository<DiscoverySession>,
    @InjectRepository(ScanJob)
    private readonly jobs: Repository<ScanJob>,
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
    private readonly fusion: FusionService,
  ) {}

  /**
   * Plant a synthetic enterprise discovery in `tenantId`'s namespace:
   *
   *     ISP1 (ASR 9001)            ISP2 (ASR 9001)
   *         │                         │
   *      ASA-8456 ────HA──── ASA-8456-S       (VRRP perimeter)
   *         │     ╲       ╱   │
   *         │      ╲     ╱    │
   *         │   ASAv-DMZ-1───Serv-DMZ-1
   *         │                  │
   *     vIOS-Ser-1 ─── vIOS-Ser-2  (DC, OSPF Area 0)
   *         │            │
   *         └─ Server-1 ─┘
   *         │            │
   *     vIOS-Core-I ─── vIOS-Core-II   (campus core)
   *         │   ╲       ╱   │
   *         │    ╳     ╳    │
   *     vIOS-Dis-I ─── vIOS-Dis-II    (distribution)
   *         │   ╲       ╱   │
   *         │    ╳     ╳    │
   *     OpenSwitch-Acc-1   OpenSwitch-Acc-2
   *      │       │           │       │
   *     PC1    PC2         PC3     PC4
   *
   * Returns the session id so callers can verify the fusion.
   */
  async seed(tenantId: string, actor: string): Promise<{ sessionId: string; observations: number }> {
    const collectorId = uuid();
    const job = await this.jobs.save(
      this.jobs.create({
        tenantId,
        collectorId,
        pillar: 'firewall',
        targetSpec: { demo: true, topology: 'enterprise' },
        credentialRefs: [],
        status: 'completed' as ScanJobStatus,
        statusReason: 'demo seed (enterprise topology)',
      }),
    );
    const session = await this.sessions.save(
      this.sessions.create({
        tenantId,
        scanJobId: job.id,
        collectorId,
        pillar: 'firewall',
        endedAt: new Date(),
        observationCount: 0,
      }),
    );

    const obs = this.buildEnterpriseObservations(tenantId, session.id, collectorId, new Date());

    await this.observations.insert(obs);
    await this.sessions.update({ id: session.id }, { observationCount: obs.length });
    await this.fusion.fuseSession(session.id);

    this.logger.log(
      `demo seed for tenant ${tenantId} by ${actor}: session=${session.id} observations=${obs.length}`,
    );
    return { sessionId: session.id, observations: obs.length };
  }

  /**
   * Wipe every row that came out of a demo-seed run for this tenant —
   * the scan jobs (`targetSpec.demo === true`), their sessions, every
   * observation in those sessions, and every typed-table row that
   * fusion produced from those observations (devices + their
   * interfaces / IP bindings / open ports / events, plus any
   * neighbour edges that touch one of those devices).
   *
   * Real discovery data is untouched: we scope by the demo flag on the
   * scan-job row, then derive device identity keys from the
   * observations that those sessions actually wrote — never by name or
   * by guessing.
   */
  async clear(tenantId: string, actor: string): Promise<{
    scanJobs: number;
    sessions: number;
    observations: number;
    devices: number;
    edges: number;
  }> {
    const allJobs = await this.jobs.find({ where: { tenantId } });
    const demoJobs = allJobs.filter((j) => (j.targetSpec as any)?.demo === true);
    if (demoJobs.length === 0) {
      return { scanJobs: 0, sessions: 0, observations: 0, devices: 0, edges: 0 };
    }
    const jobIds = demoJobs.map((j) => j.id);

    const demoSessions = await this.sessions.find({
      where: { scanJobId: In(jobIds) },
      select: ['id'],
    });
    const sessionIds = demoSessions.map((s) => s.id);

    // Harvest the identity keys this seeder actually wrote so we delete
    // exactly those devices (and nothing else).
    let identityKeys: string[] = [];
    if (sessionIds.length > 0) {
      const deviceObs = await this.observations.find({
        where: { sessionId: In(sessionIds), subjectKind: 'device' },
        select: ['subjectKey'],
      });
      identityKeys = Array.from(new Set(deviceObs.map((o) => o.subjectKey).filter(Boolean)));
    }

    let deviceIds: string[] = [];
    if (identityKeys.length > 0) {
      const devs = await this.devices.find({
        where: { tenantId, identityKey: In(identityKeys) },
        select: ['id'],
      });
      deviceIds = devs.map((d) => d.id);
    }

    let edgesDeleted = 0;
    if (deviceIds.length > 0) {
      await this.events.delete({ deviceId: In(deviceIds) });
      await this.openPorts.delete({ deviceId: In(deviceIds) });
      await this.ipBindings.delete({ deviceId: In(deviceIds) });
      await this.interfaces.delete({ deviceId: In(deviceIds) });
      // Edges can reference a demo device on either side; two scoped
      // deletes are simpler — and ORM-safe — than a raw OR clause that
      // would need column-name quoting.
      const fromRes = await this.edges.delete({ fromDeviceId: In(deviceIds) });
      const toRes = await this.edges.delete({ toDeviceId: In(deviceIds) });
      edgesDeleted = (fromRes.affected ?? 0) + (toRes.affected ?? 0);
      await this.devices.delete({ id: In(deviceIds) });
    }

    let observationsDeleted = 0;
    if (sessionIds.length > 0) {
      const obsRes = await this.observations.delete({ sessionId: In(sessionIds) });
      observationsDeleted = obsRes.affected ?? 0;
      await this.sessions.delete({ id: In(sessionIds) });
    }
    await this.jobs.delete({ id: In(jobIds) });

    this.logger.log(
      `demo clear for tenant ${tenantId} by ${actor}: scanJobs=${jobIds.length} sessions=${sessionIds.length} observations=${observationsDeleted} devices=${deviceIds.length} edges=${edgesDeleted}`,
    );
    return {
      scanJobs: jobIds.length,
      sessions: sessionIds.length,
      observations: observationsDeleted,
      devices: deviceIds.length,
      edges: edgesDeleted,
    };
  }

  // --------------------------------------------------------------------
  // Enterprise topology builder
  //
  // Every box that would speak SNMP gets a `device.snmp_identity`
  // observation; every L2 link visible to LLDP gets a `link.lldp`
  // observation. PCs and the DC/DMZ servers also get a couple of
  // `open_port.service` rows so the right-hand detail panel has
  // something to show.
  // --------------------------------------------------------------------
  private buildEnterpriseObservations(
    tenantId: string,
    sessionId: string,
    collectorId: string,
    seenAt: Date,
  ): Partial<Observation>[] {
    const mk = (
      subjectKind: string,
      subjectKey: string,
      attribute: string,
      value: any,
    ): Partial<Observation> => ({
      tenantId,
      sessionId,
      collectorId,
      subjectKind,
      subjectKey,
      attribute,
      value,
      seenAt,
    });

    type Box = {
      chassisId: string;
      sysName: string;
      sysDescr: string;
      sysObjectId: string;
      model?: string;
      managementIp?: string;
    };

    // Every managed device in the reference diagram. sysDescr is chosen
    // so guessKind() classifies the node as the kind we want.
    const boxes: Box[] = [
      // ----- ISP edge -----
      {
        chassisId: 'ISP1-ASR-9001',
        sysName: 'ISP1',
        sysDescr: 'Cisco IOS XR Software, Aggregation Services Router ASR 9001',
        sysObjectId: '1.3.6.1.4.1.9.1.1638',
        model: 'ASR 9001',
        managementIp: '192.0.2.1',
      },
      {
        chassisId: 'ISP2-ASR-9001',
        sysName: 'ISP2',
        sysDescr: 'Cisco IOS XR Software, Aggregation Services Router ASR 9001',
        sysObjectId: '1.3.6.1.4.1.9.1.1638',
        model: 'ASR 9001',
        managementIp: '198.51.100.1',
      },
      // ----- Perimeter ASA VRRP pair -----
      {
        chassisId: 'ASA-8456-A',
        sysName: 'ASA-8456',
        sysDescr: 'Cisco Adaptive Security Appliance 8.4(5)',
        sysObjectId: '1.3.6.1.4.1.9.1.745',
        model: 'ASA 8456',
        managementIp: '10.99.1.1',
      },
      {
        chassisId: 'ASA-8456-B',
        sysName: 'ASA-8456-S',
        sysDescr: 'Cisco Adaptive Security Appliance 8.4(5)',
        sysObjectId: '1.3.6.1.4.1.9.1.745',
        model: 'ASA 8456',
        managementIp: '10.99.1.2',
      },
      // ----- Data center L3 -----
      {
        chassisId: 'VIOS-SER-1',
        sysName: 'vIOS-Ser-1',
        sysDescr: 'Cisco IOS XE Software, Aggregation Services Router IOSv',
        sysObjectId: '1.3.6.1.4.1.9.1.222',
        model: 'IOSv',
        managementIp: '172.16.6.1',
      },
      {
        chassisId: 'VIOS-SER-2',
        sysName: 'vIOS-Ser-2',
        sysDescr: 'Cisco IOS XE Software, Aggregation Services Router IOSv',
        sysObjectId: '1.3.6.1.4.1.9.1.222',
        model: 'IOSv',
        managementIp: '172.16.6.2',
      },
      // ----- DC server -----
      {
        chassisId: 'SERVER-1-DC',
        sysName: 'Server-1',
        sysDescr: 'Ubuntu Server 22.04 LTS — Web/App',
        sysObjectId: '1.3.6.1.4.1.8072.3.2.10',
        model: 'PowerEdge R740',
        managementIp: '172.16.5.10',
      },
      // ----- Campus core -----
      {
        chassisId: 'VIOS-CORE-1',
        sysName: 'vIOS-Core-I',
        sysDescr: 'Cisco IOS Software, Catalyst L3 Switch 9300',
        sysObjectId: '1.3.6.1.4.1.9.1.2370',
        model: 'Catalyst 9300',
        managementIp: '10.10.0.1',
      },
      {
        chassisId: 'VIOS-CORE-2',
        sysName: 'vIOS-Core-II',
        sysDescr: 'Cisco IOS Software, Catalyst L3 Switch 9300',
        sysObjectId: '1.3.6.1.4.1.9.1.2370',
        model: 'Catalyst 9300',
        managementIp: '10.10.0.2',
      },
      // ----- Campus distribution -----
      {
        chassisId: 'VIOS-DIS-1',
        sysName: 'vIOS-Dis-I',
        sysDescr: 'Cisco IOS Software, Catalyst L3 Switch 3850',
        sysObjectId: '1.3.6.1.4.1.9.1.1745',
        model: 'Catalyst 3850',
        managementIp: '10.10.1.1',
      },
      {
        chassisId: 'VIOS-DIS-2',
        sysName: 'vIOS-Dis-II',
        sysDescr: 'Cisco IOS Software, Catalyst L3 Switch 3850',
        sysObjectId: '1.3.6.1.4.1.9.1.1745',
        model: 'Catalyst 3850',
        managementIp: '10.10.1.2',
      },
      // ----- Campus access -----
      {
        chassisId: 'OPENSW-ACC-1',
        sysName: 'OpenSwitch-Acc-1',
        sysDescr: 'OpenSwitch v3.0.0 — Catalyst 2960-X compatible access switch',
        sysObjectId: '1.3.6.1.4.1.9.1.1208',
        model: '2960-X',
        managementIp: '10.10.2.1',
      },
      {
        chassisId: 'OPENSW-ACC-2',
        sysName: 'OpenSwitch-Acc-2',
        sysDescr: 'OpenSwitch v3.0.0 — Catalyst 2960-X compatible access switch',
        sysObjectId: '1.3.6.1.4.1.9.1.1208',
        model: '2960-X',
        managementIp: '10.10.2.2',
      },
      // ----- DMZ -----
      {
        chassisId: 'ASAV-DMZ-1',
        sysName: 'ASAv-DMZ-1',
        sysDescr: 'Cisco Adaptive Security Appliance Virtual 9.16',
        sysObjectId: '1.3.6.1.4.1.9.1.2031',
        model: 'ASAv',
        managementIp: '10.1.1.145',
      },
      {
        chassisId: 'SERV-DMZ-1',
        sysName: 'Serv-DMZ-1',
        sysDescr: 'Ubuntu Server 22.04 LTS — DMZ web app',
        sysObjectId: '1.3.6.1.4.1.8072.3.2.10',
        model: 'PowerEdge R640',
        managementIp: '10.1.1.146',
      },
      // ----- PCs (would normally come from active scanner, but we plant
      // them as snmp_identity so they sit on the right side of LLDP edges
      // with the correct kind=workstation) -----
      {
        chassisId: 'PC1-WS',
        sysName: 'PC1',
        sysDescr: 'Microsoft Windows 10 Pro Workstation',
        sysObjectId: '1.3.6.1.4.1.311',
        model: 'EliteDesk 800',
        managementIp: '192.168.10.11',
      },
      {
        chassisId: 'PC2-WS',
        sysName: 'PC2',
        sysDescr: 'Microsoft Windows 10 Pro Workstation',
        sysObjectId: '1.3.6.1.4.1.311',
        model: 'EliteDesk 800',
        managementIp: '192.168.10.12',
      },
      {
        chassisId: 'PC3-WS',
        sysName: 'PC3',
        sysDescr: 'Microsoft Windows 11 Pro Workstation',
        sysObjectId: '1.3.6.1.4.1.311',
        model: 'OptiPlex 7080',
        managementIp: '192.168.20.13',
      },
      {
        chassisId: 'PC4-WS',
        sysName: 'PC4',
        sysDescr: 'Apple Mac OS Sonoma 14.4 Workstation',
        sysObjectId: '1.3.6.1.4.1.63',
        model: 'iMac',
        managementIp: '192.168.20.14',
      },
    ];

    // L2 links visible to LLDP. (Local interface, peer interface) are
    // synthesised — they don't have to match real port numbering for
    // the graph to render correctly.
    type Link = {
      a: string; aPort: number; aPortName: string;
      b: string; bPort: number; bPortName: string;
    };
    const links: Link[] = [
      // ISP ↔ ASA perimeter
      { a: 'ISP1-ASR-9001',  aPort: 1, aPortName: 'Gi0/0/0/0', b: 'ASA-8456-A', bPort: 1, bPortName: 'GigabitEthernet0/0' },
      { a: 'ISP2-ASR-9001',  aPort: 1, aPortName: 'Gi0/0/0/0', b: 'ASA-8456-B', bPort: 1, bPortName: 'GigabitEthernet0/0' },
      // ASA HA / failover link
      { a: 'ASA-8456-A',     aPort: 9, aPortName: 'GigabitEthernet0/8', b: 'ASA-8456-B', bPort: 9, bPortName: 'GigabitEthernet0/8' },
      // ASA ↔ DC core
      { a: 'ASA-8456-A',     aPort: 2, aPortName: 'GigabitEthernet0/1', b: 'VIOS-SER-1', bPort: 1, bPortName: 'Gi0/0' },
      { a: 'ASA-8456-B',     aPort: 2, aPortName: 'GigabitEthernet0/1', b: 'VIOS-SER-2', bPort: 1, bPortName: 'Gi0/0' },
      // ASA ↔ DMZ ASA
      { a: 'ASA-8456-A',     aPort: 3, aPortName: 'GigabitEthernet0/2', b: 'ASAV-DMZ-1', bPort: 1, bPortName: 'GigabitEthernet0/0' },
      // DMZ
      { a: 'ASAV-DMZ-1',     aPort: 2, aPortName: 'GigabitEthernet0/1', b: 'SERV-DMZ-1', bPort: 1, bPortName: 'eno1' },
      // DC L3 pair link + server
      { a: 'VIOS-SER-1',     aPort: 2, aPortName: 'Gi0/1', b: 'VIOS-SER-2', bPort: 2, bPortName: 'Gi0/1' },
      { a: 'VIOS-SER-1',     aPort: 3, aPortName: 'Gi0/2', b: 'SERVER-1-DC', bPort: 1, bPortName: 'eno1' },
      // DC core uplink to campus core
      { a: 'VIOS-SER-1',     aPort: 4, aPortName: 'Gi0/3', b: 'VIOS-CORE-1', bPort: 1, bPortName: 'TenGigE1/0/1' },
      { a: 'VIOS-SER-2',     aPort: 4, aPortName: 'Gi0/3', b: 'VIOS-CORE-2', bPort: 1, bPortName: 'TenGigE1/0/1' },
      // Campus core pair link
      { a: 'VIOS-CORE-1',    aPort: 2, aPortName: 'TenGigE1/0/2', b: 'VIOS-CORE-2', bPort: 2, bPortName: 'TenGigE1/0/2' },
      // Core ↔ Distribution (full mesh)
      { a: 'VIOS-CORE-1',    aPort: 3, aPortName: 'TenGigE1/0/3', b: 'VIOS-DIS-1',  bPort: 1, bPortName: 'TenGigE1/0/1' },
      { a: 'VIOS-CORE-1',    aPort: 4, aPortName: 'TenGigE1/0/4', b: 'VIOS-DIS-2',  bPort: 1, bPortName: 'TenGigE1/0/1' },
      { a: 'VIOS-CORE-2',    aPort: 3, aPortName: 'TenGigE1/0/3', b: 'VIOS-DIS-1',  bPort: 2, bPortName: 'TenGigE1/0/2' },
      { a: 'VIOS-CORE-2',    aPort: 4, aPortName: 'TenGigE1/0/4', b: 'VIOS-DIS-2',  bPort: 2, bPortName: 'TenGigE1/0/2' },
      // Distribution pair link
      { a: 'VIOS-DIS-1',     aPort: 3, aPortName: 'TenGigE1/0/3', b: 'VIOS-DIS-2',  bPort: 3, bPortName: 'TenGigE1/0/3' },
      // Distribution ↔ Access (mesh)
      { a: 'VIOS-DIS-1',     aPort: 4, aPortName: 'Gi1/0/4', b: 'OPENSW-ACC-1', bPort: 25, bPortName: 'Gi0/25' },
      { a: 'VIOS-DIS-1',     aPort: 5, aPortName: 'Gi1/0/5', b: 'OPENSW-ACC-2', bPort: 25, bPortName: 'Gi0/25' },
      { a: 'VIOS-DIS-2',     aPort: 4, aPortName: 'Gi1/0/4', b: 'OPENSW-ACC-1', bPort: 26, bPortName: 'Gi0/26' },
      { a: 'VIOS-DIS-2',     aPort: 5, aPortName: 'Gi1/0/5', b: 'OPENSW-ACC-2', bPort: 26, bPortName: 'Gi0/26' },
      // Access ↔ PCs
      { a: 'OPENSW-ACC-1',   aPort: 1, aPortName: 'Gi0/1', b: 'PC1-WS', bPort: 1, bPortName: 'eth0' },
      { a: 'OPENSW-ACC-1',   aPort: 2, aPortName: 'Gi0/2', b: 'PC2-WS', bPort: 1, bPortName: 'eth0' },
      { a: 'OPENSW-ACC-2',   aPort: 1, aPortName: 'Gi0/1', b: 'PC3-WS', bPort: 1, bPortName: 'eth0' },
      { a: 'OPENSW-ACC-2',   aPort: 2, aPortName: 'Gi0/2', b: 'PC4-WS', bPort: 1, bPortName: 'Wi-Fi' },
    ];

    // A couple of open ports per server / PC so the detail panel shows
    // something interesting.
    type Port = { ip: string; port: number; service: string; banner?: string; tlsCertCn?: string; tlsCertSans?: string[] };
    const ports: Port[] = [
      { ip: '172.16.5.10',  port: 22,  service: 'ssh',  banner: 'SSH-2.0-OpenSSH_8.4p1 Ubuntu' },
      { ip: '172.16.5.10',  port: 443, service: 'tls',  tlsCertCn: 'app.corp.local', tlsCertSans: ['app.corp.local', 'app.internal'] },
      { ip: '10.1.1.146',   port: 80,  service: 'http', banner: 'nginx/1.22.1' },
      { ip: '10.1.1.146',   port: 443, service: 'tls',  tlsCertCn: 'dmz.corp.local', tlsCertSans: ['dmz.corp.local'] },
      { ip: '192.168.10.11', port: 445, service: 'smb' },
      { ip: '192.168.10.11', port: 3389, service: 'rdp' },
      { ip: '192.168.10.12', port: 445, service: 'smb' },
      { ip: '192.168.20.13', port: 445, service: 'smb' },
      { ip: '192.168.20.13', port: 3389, service: 'rdp' },
      { ip: '192.168.20.14', port: 22,  service: 'ssh',  banner: 'SSH-2.0-OpenSSH_9.0 macOS' },
    ];

    const out: Partial<Observation>[] = [];

    // 1) Device identity + a primary management interface + IP binding.
    for (const b of boxes) {
      out.push(
        mk('device', `chassis:${b.chassisId}`, 'snmp_identity', {
          chassisId: b.chassisId,
          chassisSerial: b.chassisId,
          chassisModel: b.model,
          sysName: b.sysName,
          sysDescr: b.sysDescr,
          sysObjectId: b.sysObjectId,
          managementIp: b.managementIp,
        }),
      );
      out.push(
        mk('interface', `chassis:${b.chassisId}|if:1`, 'config', {
          index: 1,
          name: 'mgmt0',
          type: 'ethernet',
          speedBps: 1_000_000_000,
          adminStatus: 'up',
          operStatus: 'up',
          mac: macFor(b.chassisId),
        }),
      );
      if (b.managementIp) {
        out.push(
          mk('ip_binding', `chassis:${b.chassisId}|if:1|ip:${b.managementIp}`, 'config', {
            ifIndex: 1,
            ip: b.managementIp,
            prefixLen: 24,
          }),
        );
      }
    }

    // 2) LLDP edges, each emitted twice (once per side) so directionality
    //    doesn't matter and dedup is the fusion's problem.
    for (const l of links) {
      out.push(
        mk('link', `chassis:${l.a}|port:${l.aPort}|peer-chassis:${l.b}`, 'lldp', {
          localChassisId: l.a,
          localPort: l.aPort,
          peerChassisId: l.b,
          peerPortId: l.bPortName,
          peerSysName: nameFor(boxes, l.b),
        }),
      );
    }

    // 3) Open ports for the servers + PCs.
    for (const p of ports) {
      out.push(
        mk('open_port', `ip:${p.ip}|port:${p.port}`, 'service', {
          port: p.port,
          protocol: 'tcp',
          service: p.service,
          banner: p.banner,
          tlsCertCn: p.tlsCertCn,
          tlsCertSans: p.tlsCertSans,
        }),
      );
    }

    return out;
  }
}

// Deterministic synthetic MAC so re-seeding produces the same identity.
function macFor(chassisId: string): string {
  let h = 0;
  for (let i = 0; i < chassisId.length; i++) h = (h * 31 + chassisId.charCodeAt(i)) | 0;
  const bytes = [
    0x02, // locally administered
    (h >>> 24) & 0xff,
    (h >>> 16) & 0xff,
    (h >>> 8) & 0xff,
    h & 0xff,
    chassisId.length & 0xff,
  ];
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
}

function nameFor(boxes: Array<{ chassisId: string; sysName: string }>, chassisId: string): string {
  return boxes.find((b) => b.chassisId === chassisId)?.sysName ?? chassisId;
}
