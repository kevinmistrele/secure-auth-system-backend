# Overview

Multi-tenant authentication & authorization service. Users belong to one or more **organizations** (tenants) through **memberships** that carry a **role** (`OWNER`, `ADMIN`, `MEMBER`). A login session is always bound to exactly one organization: the JWT carries `sub`, `email`, `tenantId` and `role`.

Request lifecycle:

```
request
  → JwtAuthGuard        verifies the token (skipped for @Public routes)
  → RolesGuard          coarse role check (@Roles)
  → PermissionsGuard    fine-grained check (@RequirePermission, role → permission map)
  → controller          reads identity via @CurrentUser()/@CurrentTenant()
  → service             runs tenant queries inside TenantPrismaService.withTenant
  → PostgreSQL          RLS policies re-enforce the tenant boundary
```

Key flows:

- **Register** creates user + organization + OWNER membership atomically.
- **Login/refresh** issue an access token (15 min) plus an opaque rotating refresh token (stored hashed, revocable, reuse-detected).
- **Invitations**: an admin invites an email with a role; the invited user (any authenticated account with that email) accepts by token and becomes a member.
- **Audit logs**: every significant action is recorded per tenant — this is the RLS-protected business table the e2e suite uses to prove isolation.

Read next: [tenancy-and-rls.md](./tenancy-and-rls.md), [project-structure.md](./project-structure.md).
