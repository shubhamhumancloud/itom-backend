import { IsArray, IsOptional, IsString } from 'class-validator';

export class SetupUserDto {
  @IsString()
  tenantId: string;

  @IsString()
  userId: string;

  @IsOptional()
  @IsString()
  email?: string;

  @IsOptional()
  @IsString()
  fullName?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  roles?: string[];
}
