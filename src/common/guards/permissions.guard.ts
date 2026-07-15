import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSION_KEY } from '../decorators/require-permission.decorator';
import { Permission, roleHasPermission } from '../rbac/permissions';
import { AuthenticatedUser } from '../types/authenticated-user';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const permission = this.reflector.getAllAndOverride<
      Permission | undefined
    >(PERMISSION_KEY, [context.getHandler(), context.getClass()]);
    if (!permission) {
      return true;
    }
    const { user } = context
      .switchToHttp()
      .getRequest<{ user?: AuthenticatedUser }>();
    return !!user && roleHasPermission(user.role, permission);
  }
}
