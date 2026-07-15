# ADR 0002 — Tenant context is transaction-scoped, not connection-scoped

## Context

The naive design runs `SET app.current_tenant = ...` once per request in a middleware. Prisma (like any pool) reuses connections across requests, so a per-connection `SET` can leak request A's tenant into request B — a catastrophic cross-tenant failure mode. Nest middleware also runs before guards, i.e. before the JWT is verified, so it would have to parse the token itself.

## Decision

`TenantPrismaService.withTenant(tenantId, fn)` opens an interactive transaction and runs `SELECT set_config('app.current_tenant', $id, true)` — the parameter `true` makes it transaction-local (`SET LOCAL` semantics), automatically cleared at commit/rollback. Controllers obtain the tenant from the verified JWT via `@CurrentTenant()` and pass it to services explicitly.

## Consequences

- No leakage between pooled connections; safe under pgbouncer-style pooling too.
- No hidden request-scoped state: services are plain functions of their arguments, easy to test.
- One transaction per `withTenant` call — batch a request's queries into one call.
