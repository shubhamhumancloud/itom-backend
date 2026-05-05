import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Tenant } from './tenant.entity';
import { TenantUser } from './tenant-user.entity';
import { Agent } from '../../agents/agent.entity';
import { SetupTenantDto } from './dto/setup-tenant.dto';
import { SetupUserDto } from './dto/setup-user.dto';
import { TenantStatusDto } from './dto/tenant-status.dto';

@Injectable()
export class OnboardingService {
  constructor(
    @InjectRepository(Tenant)
    private readonly tenants: Repository<Tenant>,
    @InjectRepository(TenantUser)
    private readonly tenantUsers: Repository<TenantUser>,
    @InjectRepository(Agent)
    private readonly agents: Repository<Agent>,
  ) {}

  async backfillTenant(tenantId: string) {
    const result = await this.agents
      .createQueryBuilder()
      .update(Agent)
      .set({ tenantId })
      .where('"tenantId" IS NULL')
      .execute();
    return { tenantId, updatedAgents: result.affected ?? 0 };
  }

  async setupTenant(dto: SetupTenantDto) {
    const existing = await this.tenants.findOne({
      where: { tenantId: dto.tenantId },
    });
    if (existing) {
      const updated = this.tenants.merge(existing, {
        orgId: dto.orgId ?? existing.orgId,
        name: dto.name ?? existing.name,
        plan: dto.plan ?? existing.plan,
        status: 'active',
      });
      await this.tenants.save(updated);
      return { tenant: updated, created: false };
    }
    const tenant = this.tenants.create({
      tenantId: dto.tenantId,
      orgId: dto.orgId,
      name: dto.name,
      plan: dto.plan,
      status: 'active',
    });
    await this.tenants.save(tenant);
    return { tenant, created: true };
  }

  async setupUser(dto: SetupUserDto) {
    const tenant = await this.tenants.findOne({
      where: { tenantId: dto.tenantId },
    });
    if (!tenant) {
      throw new NotFoundException(`Tenant ${dto.tenantId} not provisioned`);
    }
    const existing = await this.tenantUsers.findOne({
      where: { tenantId: dto.tenantId, userId: dto.userId },
    });
    if (existing) {
      const updated = this.tenantUsers.merge(existing, {
        email: dto.email ?? existing.email,
        fullName: dto.fullName ?? existing.fullName,
        roles: dto.roles ?? existing.roles,
      });
      await this.tenantUsers.save(updated);
      return { user: updated, created: false };
    }
    const user = this.tenantUsers.create(dto);
    await this.tenantUsers.save(user);
    return { user, created: true };
  }

  async getStatus(tenantId: string, orgId?: string) {
    const tenant = await this.tenants.findOne({ where: { tenantId } });
    if (!tenant) {
      return {
        tenantId,
        orgId: orgId ?? null,
        provisioned: false,
        status: 'not_provisioned',
        userCount: 0,
      };
    }
    const userCount = await this.tenantUsers.count({ where: { tenantId } });
    return {
      tenantId: tenant.tenantId,
      orgId: tenant.orgId,
      provisioned: true,
      status: tenant.status,
      userCount,
    };
  }

  async setTenantStatus(dto: TenantStatusDto) {
    const tenant = await this.tenants.findOne({
      where: { tenantId: dto.tenantId },
    });
    if (!tenant) {
      throw new NotFoundException(`Tenant ${dto.tenantId} not provisioned`);
    }
    tenant.status = dto.status;
    await this.tenants.save(tenant);
    return { tenantId: tenant.tenantId, status: tenant.status };
  }
}
