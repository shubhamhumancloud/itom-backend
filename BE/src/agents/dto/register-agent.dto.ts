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
  agentVersion?: string;

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
