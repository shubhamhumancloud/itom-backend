import {
  IsArray,
  IsISO8601,
  IsNumber,
  IsString,
  Max,
  Min,
  ValidateNested,
  ArrayMinSize,
  IsOptional,
  IsInt,
  IsUUID,
} from 'class-validator';
import { Type } from 'class-transformer';

export class NetworkSampleDto {
  @IsString()
  interfaceName: string;

  @IsInt()
  @Min(0)
  bytesSent: number;

  @IsInt()
  @Min(0)
  bytesRecv: number;

  @IsInt()
  @Min(0)
  packetsSent: number;

  @IsInt()
  @Min(0)
  packetsRecv: number;
}

export class DiskSampleDto {
  @IsString()
  mountpoint: string;

  @IsNumber()
  @Min(0)
  @Max(100)
  usedPercent: number;

  @IsInt()
  @Min(0)
  usedBytes: number;

  @IsInt()
  @Min(0)
  totalBytes: number;
}

export class SampleDto {
  @IsISO8601()
  timestamp: string;

  @IsNumber()
  @Min(0)
  @Max(100)
  cpuPercent: number;

  @IsNumber()
  @Min(0)
  @Max(100)
  memoryPercent: number;

  @IsNumber()
  @Min(0)
  @Max(100)
  diskPercent: number;

  @IsOptional()
  @IsInt()
  @Min(0)
  memAvailableBytes?: number;

  @IsOptional()
  @IsNumber()
  @Min(0)
  loadAvg1m?: number;

  @IsOptional()
  @IsInt()
  @Min(0)
  processCount?: number;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => NetworkSampleDto)
  network?: NetworkSampleDto[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => DiskSampleDto)
  disks?: DiskSampleDto[];
}

export class CreateMetricsDto {
  @IsString()
  agentId: string;

  @IsOptional()
  @IsUUID('4')
  requestId?: string;

  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => SampleDto)
  samples: SampleDto[];
}
