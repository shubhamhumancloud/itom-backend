import { IsIn, IsString } from 'class-validator';

export class TenantStatusDto {
  @IsString()
  tenantId: string;

  @IsIn(['active', 'suspended'])
  status: 'active' | 'suspended';
}
