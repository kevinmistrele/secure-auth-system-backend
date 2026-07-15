# Tests

- **Unit** (`src/**/*.spec.ts`): pure logic — the RBAC map, guards with mocked `Reflector`/context. No database, no Nest app.
- **E2E** (`test/*.e2e-spec.ts`): full Nest app against a real Postgres with the real migrations. This is where auth, RBAC and RLS are proven; do not mock Prisma here — a mocked database cannot prove RLS.
- The tenant-isolation suite is the contract of the repo. Any change to auth, guards, tenant context or migrations must keep it green and, when adding a new tenant-scoped table or permission, must extend it.
- Test names state the guarantee ("refuses to write a row into another tenant"), not the implementation.
- Prefer driving through HTTP (`supertest`); reach into services/DB only to prove database-level behavior (e.g. unfiltered `findMany` under `withTenant`).
