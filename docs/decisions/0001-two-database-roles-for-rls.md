# ADR 0001 — Two database roles: migration owner + RLS-enforced `app_user`

## Context

PostgreSQL RLS does not apply to superusers, and by default not to the table owner either. The docker-compose `postgres` user (which Prisma Migrate needs for DDL) is a superuser — if the application also connected as it, every policy would be silently bypassed and the project's core guarantee would be theater.

## Decision

Two roles, two connection strings:

- `DATABASE_URL` (owner/superuser): Prisma Migrate and the **auth plane** (`PrismaService`) — flows that legitimately run before a tenant context exists.
- `APP_DATABASE_URL` (`app_user`, created in the init migration with plain CRUD grants, no `BYPASSRLS`): the **tenant plane** (`TenantPrismaService`) — every tenant-scoped query. Tables additionally set `FORCE ROW LEVEL SECURITY` so a future owner-connection mistake still can't bypass policies (superusers excepted).

## Consequences

- RLS is actually enforced at runtime, provable by the e2e suite.
- The auth plane is a narrow, documented exception (see tenancy-and-rls.md); routing tenant queries through it is the bug class the review checklist hunts for.
- Dev credentials for `app_user` are created in the migration; production overrides `APP_DATABASE_URL`.
