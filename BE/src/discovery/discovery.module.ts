import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanJob } from './entities/scan-job.entity';
import { DiscoverySession } from './entities/discovery-session.entity';
import { Observation } from './entities/observation.entity';
import { Credential } from './entities/credential.entity';
import { AuditLog } from './entities/audit-log.entity';
import { Collector } from './entities/collector.entity';
import { CredentialVaultService } from './credential-vault.service';
import { AuditLogService } from './audit-log.service';
import { ScanJobService } from './scan-job.service';
import { CollectorService } from './collector.service';
import { ObservationIngestService } from './observation-ingest.service';
import { SigningService } from './signing.service';
import { ScanJobDispatcherService } from './scan-job-dispatcher.service';
import { DiscoveryController } from './discovery.controller';
import { DiscoveryGateway } from './ws/discovery.gateway';

/**
 * Discovery module — Chapter 1 (firewall ingest) state.
 *
 * What's here:
 *   - Entities for scan jobs, sessions, observations, credentials,
 *     audit log, and collectors.
 *   - Envelope-encrypted credential vault.
 *   - Ed25519 SigningService for the per-tenant CIDR allowlist.
 *   - Discovery WebSocket gateway at /v1/discovery/ws that talks to
 *     the Go itom-collector daemon.
 *   - Scan-job dispatcher that watches Postgres NOTIFY and pushes
 *     signed ScanJobAssign frames over the gateway.
 *   - ObservationIngestService that batch-inserts ScanJobChunk rows.
 *
 * What's deliberately NOT here yet (comes in Chapters 2-5):
 *   - Typed topology tables (site, subnet, device, interface, nat_rule,
 *     vpn_tunnel, …). Per chapter 1 option (a) we land raw observations
 *     only; fusion → typed rows is parked for chapter 4.
 *   - Postgres Row-Level Security policies (still service-layer
 *     tenant filtering).
 *   - SNMP / active-scan pillars.
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
    ]),
  ],
  controllers: [DiscoveryController],
  providers: [
    CredentialVaultService,
    AuditLogService,
    ScanJobService,
    CollectorService,
    ObservationIngestService,
    SigningService,
    ScanJobDispatcherService,
    DiscoveryGateway,
  ],
  exports: [
    CredentialVaultService,
    AuditLogService,
    ScanJobService,
    CollectorService,
    SigningService,
    DiscoveryGateway,
  ],
})
export class DiscoveryModule {}
