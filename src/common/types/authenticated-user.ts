import { Role } from '@prisma/client';

/** Request-scoped identity derived from the verified JWT by JwtStrategy. */
export interface AuthenticatedUser {
  userId: string;
  email: string;
  tenantId: string;
  role: Role;
}

/** Claims carried by the access token. */
export interface AccessTokenPayload {
  sub: string;
  email: string;
  tenantId: string;
  role: Role;
}
