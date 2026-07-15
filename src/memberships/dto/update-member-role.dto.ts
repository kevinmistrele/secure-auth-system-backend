import { Role } from '@prisma/client';
import { IsIn } from 'class-validator';

export class UpdateMemberRoleDto {
  /** OWNER is excluded on purpose: ownership transfer is not supported yet. */
  @IsIn([Role.ADMIN, Role.MEMBER])
  role!: typeof Role.ADMIN | typeof Role.MEMBER;
}
