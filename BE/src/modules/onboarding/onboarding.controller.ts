import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { InternalApiKeyGuard } from '../../common/guards/internal-api-key.guard';
import { OnboardingService } from './onboarding.service';
import { SetupTenantDto } from './dto/setup-tenant.dto';
import { SetupUserDto } from './dto/setup-user.dto';
import { TenantStatusDto } from './dto/tenant-status.dto';

@Controller('api/v1/onboarding')
@UseGuards(InternalApiKeyGuard)
export class OnboardingController {
  constructor(private readonly onboarding: OnboardingService) {}

  @Post('setup-tenant')
  setupTenant(@Body() dto: SetupTenantDto) {
    return this.onboarding.setupTenant(dto);
  }

  @Post('setup-user')
  setupUser(@Body() dto: SetupUserDto) {
    return this.onboarding.setupUser(dto);
  }

  @Get('status/:tenantId')
  getStatus(
    @Param('tenantId') tenantId: string,
    @Query('orgId') orgId?: string,
  ) {
    return this.onboarding.getStatus(tenantId, orgId);
  }

  @Patch('tenant-status')
  setTenantStatus(@Body() dto: TenantStatusDto) {
    return this.onboarding.setTenantStatus(dto);
  }

  @Post('backfill-tenant')
  backfillTenant(@Body() dto: { tenantId: string }) {
    return this.onboarding.backfillTenant(dto.tenantId);
  }
}
