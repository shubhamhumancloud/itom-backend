import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanJob } from './entities/scan-job.entity';
import { DiscoverySession } from './entities/discovery-session.entity';
import { Observation } from './entities/observation.entity';
import { Credential } from './entities/credential.entity';
import { AuditLog } from './entities/audit-log.entity';
import { Collector } from './entities/collector.entity';
import { Site } from './entities/site.entity';
import { Device } from './entities/device.entity';
import { NetworkInterface } from './entities/network-interface.entity';
import { IpBinding } from './entities/ip-binding.entity';
import { NeighborEdge } from './entities/neighbor-edge.entity';
import { OpenPort } from './entities/open-port.entity';
import { DiscoveryEvent } from './entities/discovery-event.entity';
import { CredentialVaultService } from './credential-vault.service';
import { AuditLogService } from './audit-log.service';
import { ScanJobService } from './scan-job.service';
import { CollectorService } from './collector.service';
import { ObservationIngestService } from './observation-ingest.service';
import { SigningService } from './signing.service';
import { ScanJobDispatcherService } from './scan-job-dispatcher.service';
import { CollectorBinaryPatcherService } from './collector-binary-patcher.service';
import { FusionService } from './fusion/fusion.service';
import { TopologyService } from './topology/topology.service';
import { TopologyController } from './topology/topology.controller';
import { DemoSeedService } from './topology/demo-seed.service';
import { DiscoveryController } from './discovery.controller';
import { DiscoveryGateway } from './ws/discovery.gateway';

/**
 * Discovery module — chapters 0-4 wired.
 *
 * Pillars in place: firewall (chapter 1 + chapter 2 SNMP crawl) and
 * active (chapter 3 sweep). Chapter 4 added the typed topology
 * tables + fusion service + topology read API + demo seeder.
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([
      ScanJob,
      DiscoverySession,
      Observation,
      Credential,
      AuditLog,
      Collector,
      Site,
      Device,
      NetworkInterface,
      IpBinding,
      NeighborEdge,
      OpenPort,
      DiscoveryEvent,
    ]),
  ],
  controllers: [DiscoveryController, TopologyController],
  providers: [
    CredentialVaultService,
    AuditLogService,
    ScanJobService,
    CollectorService,
    ObservationIngestService,
    SigningService,
    ScanJobDispatcherService,
    CollectorBinaryPatcherService,
    DiscoveryGateway,
    FusionService,
    TopologyService,
    DemoSeedService,
  ],
  exports: [
    CredentialVaultService,
    AuditLogService,
    ScanJobService,
    CollectorService,
    SigningService,
    DiscoveryGateway,
    FusionService,
    TopologyService,
  ],
})
export class DiscoveryModule {}
