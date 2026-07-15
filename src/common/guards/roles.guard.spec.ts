import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { AuthenticatedUser } from '../types/authenticated-user';
import { RolesGuard } from './roles.guard';

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

describe('RolesGuard', () => {
  let reflector: Reflector;
  let guard: RolesGuard;
  let required: Role[] | undefined;

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
    jest
      .spyOn(reflector, 'getAllAndOverride')
      .mockImplementation(() => required);
  });

  it('allows any caller when the route declares no roles', () => {
    required = undefined;
    expect(guard.canActivate(contextFor(userWithRole(Role.MEMBER)))).toBe(true);
  });

  it('allows a caller whose role is listed', () => {
    required = [Role.OWNER, Role.ADMIN];
    expect(guard.canActivate(contextFor(userWithRole(Role.ADMIN)))).toBe(true);
  });

  it('denies a caller whose role is not listed', () => {
    required = [Role.OWNER];
    expect(guard.canActivate(contextFor(userWithRole(Role.MEMBER)))).toBe(false);
  });
});
