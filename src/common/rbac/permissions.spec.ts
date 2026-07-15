import { Role } from '@prisma/client';
import { PERMISSIONS, roleHasPermission, ROLE_PERMISSIONS } from './permissions';

describe('ROLE_PERMISSIONS', () => {
  it('grants every permission to OWNER', () => {
    for (const permission of PERMISSIONS) {
      expect(roleHasPermission(Role.OWNER, permission)).toBe(true);
    }
  });

  it('lets ADMIN manage members and invitations but MEMBER only read', () => {
    expect(roleHasPermission(Role.ADMIN, 'invitations:create')).toBe(true);
    expect(roleHasPermission(Role.ADMIN, 'members:remove')).toBe(true);
    expect(roleHasPermission(Role.MEMBER, 'invitations:create')).toBe(false);
    expect(roleHasPermission(Role.MEMBER, 'audit:read')).toBe(false);
    expect(roleHasPermission(Role.MEMBER, 'members:read')).toBe(true);
  });

  it('maps every role to a defined permission list', () => {
    for (const role of Object.values(Role)) {
      expect(ROLE_PERMISSIONS[role]).toBeDefined();
    }
  });
});
