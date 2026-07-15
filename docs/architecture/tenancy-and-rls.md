# Tenancy & Row-Level Security

The isolation guarantee of this project lives **in PostgreSQL**, not in application code. Even if a service forgets a `WHERE` clause, the database returns zero foreign rows.

## The two planes

| Plane | Prisma client | DB role | RLS | Who may use it |
| --- | --- | --- | --- | --- |
| Auth plane | `PrismaService` | migration owner (`DATABASE_URL`) | bypassed | register, login, refresh, password reset, invitation accept, "list my organizations" |
| Tenant plane | `TenantPrismaService` | `app_user` (`APP_DATABASE_URL`) | **enforced** | everything else |

The auth plane exists because those flows run **before a tenant context exists** (login does not know the tenant yet; accepting an invitation targets an organization the user is not a member of yet). It is the documented exception — any other code path touching `memberships`, `invitations`, `organizations` or `audit_logs` must go through `TenantPrismaService.withTenant`.

## How the tenant context is set

```ts
tenantPrisma.withTenant(tenantId, (tx) => tx.auditLog.findMany());
```

`withTenant` opens a transaction and runs `SELECT set_config('app.current_tenant', $tenantId, true)`. The third argument (`true`) makes the setting **transaction-local** (the `SET LOCAL` equivalent). With pooled connections, a per-connection `SET` would leak one request's tenant into the next request that reuses the connection — see ADR 0002.

The `tenantId` argument comes from `@CurrentTenant()`, which reads the **verified JWT** (`JwtStrategy` is the only code that parses claims). Never accept a tenant id from the body, query string or headers.

## The policies

Every tenant-scoped table (`organizations`, `memberships`, `invitations`, `audit_logs`) has:

```sql
ALTER TABLE t ENABLE ROW LEVEL SECURITY;
ALTER TABLE t FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON t
  USING (organization_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
```

- `current_setting(..., true)` returns NULL instead of erroring when the setting is absent, so **no context = zero rows** — fail closed.
- `WITH CHECK` blocks cross-tenant **writes**, not only reads.
- `organizations` uses `id = current_tenant` (the table *is* the tenant).
- Policies live in `prisma/migrations/*/migration.sql` — Prisma's schema cannot express them.

## Un-scoped tables (on purpose)

- `users` — global identity; one account belongs to many organizations.
- `refresh_tokens` — auth plane infrastructure; opaque, hashed, never exposed via API.

## JWT claims

Access token payload: `{ sub, email, tenantId, role }`. Switching organizations issues a **new token pair** (`POST /auth/switch-tenant`); a token is always bound to exactly one tenant.
