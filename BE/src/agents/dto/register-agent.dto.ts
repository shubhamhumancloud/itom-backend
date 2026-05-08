import {
  IsString,
  IsOptional,
  IsArray,
  IsNumber,
  IsInt,
  Min,
} from 'class-validator';

export class RegisterAgentDto {
  @IsString()
  agentId: string;

  @IsString()
  @IsOptional()
  tenantId?: string;

  @IsString()
  @IsOptional()
  agentVersion?: string;

  @IsString()
  @IsOptional()
  fingerprintHash?: string;

  // Hash from the previous (MAC-based) fingerprint formula. Sent by agents
  // that upgraded in place so the backend can match the existing record
  // even though the new hash differs. Drop after one release cycle.
  @IsString()
  @IsOptional()
  legacyFingerprintHash?: string;

  @IsString()
  @IsOptional()
  hostname?: string;

  @IsString()
  @IsOptional()
  os?: string;

  @IsString()
  @IsOptional()
  arch?: string;

  @IsString()
  @IsOptional()
  platform?: string;

  @IsString()
  @IsOptional()
  platformVersion?: string;

  @IsString()
  @IsOptional()
  kernelVersion?: string;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  ethernetIPs?: string[];

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  wifiIPs?: string[];

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  macAddresses?: string[];

  @IsString()
  @IsOptional()
  cpuModel?: string;

  @IsInt()
  @Min(1)
  @IsOptional()
  cpuCores?: number;

  @IsNumber()
  @Min(0)
  @IsOptional()
  totalMemoryBytes?: number;

  @IsNumber()
  @Min(0)
  @IsOptional()
  totalDiskBytes?: number;
}
