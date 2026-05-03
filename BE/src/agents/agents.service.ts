import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Agent } from './agent.entity';
import { RegisterAgentDto } from './dto/register-agent.dto';

@Injectable()
export class AgentsService {
  private readonly logger = new Logger(AgentsService.name);

  constructor(
    @InjectRepository(Agent)
    private readonly agentsRepo: Repository<Agent>,
  ) {}

  async register(dto: RegisterAgentDto): Promise<Agent> {
    await this.agentsRepo.upsert(
      {
        agentId: dto.agentId,
        agentVersion: dto.agentVersion,
        hostname: dto.hostname,
        os: dto.os,
        arch: dto.arch,
        platform: dto.platform,
        platformVersion: dto.platformVersion,
        kernelVersion: dto.kernelVersion,
        ethernetIPs: dto.ethernetIPs,
        wifiIPs: dto.wifiIPs,
        macAddresses: dto.macAddresses,
        cpuModel: dto.cpuModel,
        cpuCores: dto.cpuCores,
        totalMemoryBytes: dto.totalMemoryBytes,
        totalDiskBytes: dto.totalDiskBytes,
      },
      ['agentId'],
    );
    this.logger.log(`registered agent=${dto.agentId} host=${dto.hostname}`);
    return this.agentsRepo.findOneBy({ agentId: dto.agentId });
  }

  async list(): Promise<Agent[]> {
    return this.agentsRepo.find({ order: { lastSeenAt: 'DESC' } });
  }

  async findOne(agentId: string): Promise<Agent | null> {
    return this.agentsRepo.findOneBy({ agentId });
  }

  async touchLastSeen(agentId: string): Promise<void> {
    await this.agentsRepo.update({ agentId }, { lastSeenAt: new Date() });
  }
}
