import { IsOptional, IsString, IsUUID } from 'class-validator';

export class SwitchTenantDto {
  @IsUUID()
  organizationId!: string;

  /** When provided, the old session's refresh token is revoked. */
  @IsOptional()
  @IsString()
  refreshToken?: string;
}
