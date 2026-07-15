import { Role } from '@prisma/client';

export const PERMISSIONS = [
  'org:read',
  'org:update',
  'members:read',
  'members:update',
  'members:remove',
  'invitations:create',
  'invitations:read',
  'invitations:revoke',
  'audit:read',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

const ADMIN_PERMISSIONS: readonly Permission[] = [
  'org:read',
  'org:update',
  'members:read',
  'members:update',
  'members:remove',
  'invitations:create',
  'invitations:read',
  'invitations:revoke',
  'audit:read',
];

export const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  [Role.OWNER]: PERMISSIONS,
  [Role.ADMIN]: ADMIN_PERMISSIONS,
  [Role.MEMBER]: ['org:read', 'members:read'],
};

export function roleHasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}
