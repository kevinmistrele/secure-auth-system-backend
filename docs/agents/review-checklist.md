# Review Checklist

Walk this before reporting done:

- [ ] No `any`; strict TypeScript holds.
- [ ] Every tenant-scoped query runs inside `TenantPrismaService.withTenant` — or is a documented auth-plane flow.
- [ ] Tenant id and role come only from the verified JWT (`@CurrentTenant()` / `@CurrentUser()`), never from body/query/headers.
- [ ] New tenant-scoped tables have `ENABLE`/`FORCE ROW LEVEL SECURITY` + `tenant_isolation` policy in a migration.
- [ ] Passwords hashed with argon2; tokens stored only as SHA-256 hashes.
- [ ] Errors don't leak existence: cross-tenant probes see 404; unauthenticated → 401; unauthorized → 403.
- [ ] Auth failures return the same message for wrong-email and wrong-password.
- [ ] New endpoints have `@RequirePermission`/`@Roles` (or an explicit reason they're open) and DTO validation.
- [ ] Significant actions write an audit log entry.
- [ ] Smallest sufficient validation ran and passed (`docs/agents/validation.md`).
- [ ] Docs still true (`AGENTS.md`, `docs/`) — updated in this change if not.
- [ ] Deliberate shortcuts marked `// ponytail: <ceiling>, <upgrade path>`.
