import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { Permission } from '../rbac/permissions';
import { AuthenticatedUser } from '../types/authenticated-user';
import { PermissionsGuard } from './permissions.guard';

function contextFor(user?: AuthenticatedUser): ExecutionContext {
  return {
    getHandler: () => ({}),
    getClass: () => ({}),
    switchToHttp: () => ({ getRequest: () => ({ user }) }),
  } as unknown as ExecutionContext;
}

function userWithRole(role: Role): AuthenticatedUser {
  return { userId: 'u1', email: 'u@example.com', tenantId: 't1', role };
}

describe('PermissionsGuard', () => {
  let reflector: Reflector;
  let guard: PermissionsGuard;
  let required: Permission | undefined;

  beforeEach(() => {
    reflector = new Reflector();
    guard = new PermissionsGuard(reflector);
    jest
      .spyOn(reflector, 'getAllAndOverride')
      .mockImplementation(() => required);
  });

  it('allows any caller when the route requires no permission', () => {
    required = undefined;
    expect(guard.canActivate(contextFor(userWithRole(Role.MEMBER)))).toBe(true);
  });

  it('allows a role that holds the required permission', () => {
    required = 'invitations:create';
    expect(guard.canActivate(contextFor(userWithRole(Role.ADMIN)))).toBe(true);
  });

  it('denies a role that lacks the required permission', () => {
    required = 'invitations:create';
    expect(guard.canActivate(contextFor(userWithRole(Role.MEMBER)))).toBe(false);
  });

  it('denies when there is no authenticated user', () => {
    required = 'members:read';
    expect(guard.canActivate(contextFor(undefined))).toBe(false);
  });
});
