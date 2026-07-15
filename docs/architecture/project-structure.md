# Project Structure

One NestJS module per concern. A new endpoint goes in the module that owns its resource; a new concern gets a new top-level module folder.

```txt
src/
  main.ts                      bootstrap: CORS, /api prefix, validation pipe, prisma filter
  app.module.ts                wires modules + the three global guards (order matters)
  auth/                        controller/service, JWT strategy, DTOs
  organizations/               org CRUD (create, list mine, current, rename)
  memberships/                 /members endpoints (list, change role, remove)
  invitations/                 create/list/revoke/accept
  audit/                       AuditService.log + GET /audit-logs
  mail/                        MailService (SMTP or console)
  prisma/                      PrismaService (auth plane), TenantPrismaService (RLS plane)
  common/
    decorators/                @Public, @Roles, @RequirePermission, @CurrentUser, @CurrentTenant
    guards/                    JwtAuthGuard, RolesGuard, PermissionsGuard
    rbac/permissions.ts        the Permission type + role → permission map
    filters/                   PrismaExceptionFilter (P2002→409, P2025→404)
    types/                     AuthenticatedUser, AccessTokenPayload
prisma/
  schema.prisma                models; tenant-scoped tables are documented as such
  migrations/                  DDL + RLS policies (SQL is the source of truth for RLS)
test/
  tenant-isolation.e2e-spec.ts the proof that tenant A cannot read tenant B
```

Conventions:

- DTOs live in `<module>/dto/` and use `class-validator`.
- Controllers do authorization via decorators and pass `@CurrentTenant()` / `@CurrentUser()` into services; services never touch the request or the token.
- Unit specs sit next to the code (`*.spec.ts`); e2e specs live in `test/`.
