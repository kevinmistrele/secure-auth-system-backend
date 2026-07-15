import { SetMetadata } from '@nestjs/common';
import { Permission } from '../rbac/permissions';

export const PERMISSION_KEY = 'permission';

/** Fine-grained RBAC: the JWT's role must map to this permission. */
export const RequirePermission = (
  permission: Permission,
): MethodDecorator & ClassDecorator => SetMetadata(PERMISSION_KEY, permission);
