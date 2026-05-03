import {
  IsString,
  IsISO8601,
  IsOptional,
  IsInt,
  Min,
  IsUUID,
} from 'class-validator';

export class HeartbeatDto {
  @IsUUID('4')
  agentId: string;

  @IsISO8601()
  timestamp: string;

  @IsString()
  @IsOptional()
  agentVersion?: string;

  @IsInt()
  @Min(0)
  @IsOptional()
  uptimeSeconds?: number;
}
