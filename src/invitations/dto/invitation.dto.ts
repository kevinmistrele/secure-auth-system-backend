import { Role } from '@prisma/client';
import { IsEmail, IsIn, IsString } from 'class-validator';

export class CreateInvitationDto {
  @IsEmail()
  email!: string;

  /** An invitation can never grant ownership. */
  @IsIn([Role.ADMIN, Role.MEMBER])
  role!: typeof Role.ADMIN | typeof Role.MEMBER;
}

export class AcceptInvitationDto {
  @IsString()
  token!: string;
}
