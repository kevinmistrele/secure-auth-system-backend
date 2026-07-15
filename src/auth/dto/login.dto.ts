import { IsEmail, IsOptional, IsString, IsUUID } from 'class-validator';

export class LoginDto {
  @IsEmail()
  email!: string;

  @IsString()
  password!: string;

  /** Which organization to log into; defaults to the user's first membership. */
  @IsOptional()
  @IsUUID()
  organizationId?: string;
}
