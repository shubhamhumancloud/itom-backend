import { IsOptional, IsString } from 'class-validator';

export class SetupTenantDto {
  @IsString()
  tenantId: string;

  @IsOptional()
  @IsString()
  orgId?: string;

  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  plan?: string;
}
