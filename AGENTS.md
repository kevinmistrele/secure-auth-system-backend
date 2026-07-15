# AGENTS.md

## Purpose

`secure-auth-backend` is a NestJS authentication/authorization service with real multi-tenant isolation: JWT claims carry tenant and role, and PostgreSQL Row-Level Security enforces isolation at the database level, independent of application code. This file defines **how** to build it — the code standard, whichever agent (Claude, Codex, Cursor, Copilot, human) is writing it.

## Commands

```bash
npm install                 # setup (Node >= 20 LTS)
docker compose up -d        # Postgres
npx prisma migrate dev
npm run start:dev
npm run typecheck
npm run lint
npm run test
npm run test:e2e
npm run build
```

Run the smallest check that proves your change works — see [Validation](#validation).

## Rule Priority

1. Explicit user request.
2. Existing code and local patterns.
3. This `AGENTS.md` and `docs/`.
4. General NestJS, TypeScript and auth/authorization best practices.

If rules conflict, mark `Pending decision` and choose the smallest safe change only when progress is still possible.

## How to Work

1. Read the code you are about to change and its neighbors before editing; prefer existing patterns over new abstractions.
2. Choose the smallest implementation that satisfies the request — climb the ladder below first.
3. Keep diffs small and reviewable; don't move or rename files unless that is the task.
4. Validate (see [Validation](#validation)), self-check against `docs/agents/review-checklist.md`, then report.

Full version: `docs/agents/workflow.md`.

## The Ladder (what NOT to build)

Stop at the first rung that holds:

1. Does this need to exist at all? Speculative need → skip it, say so in one line (YAGNI).
2. Already in this codebase? Reuse the existing guard, decorator, or `TenantPrismaService.withTenant`.
3. Does Nest's own toolkit already do it (`@nestjs/jwt`, Passport strategies, guards)? Use it before hand-rolling.
4. Does PostgreSQL itself already do it (RLS policies, constraints, unique indexes)? Enforce it at the database, not only in application code — that is this project's entire premise.
5. Does an already-installed dependency solve it (`argon2`, `class-validator`)? Use it.
6. Can it be one line? Make it one line.
7. Only then: the minimum code that works.

Mark a deliberate shortcut with a `// ponytail: <ceiling>, <upgrade path>` comment.

## Documentation Map

```txt
docs/
  agents/         how to work: workflow, validation, review checklist
  architecture/   the system: overview, project structure, dependency rules, tenancy & RLS
  standards/      the code: typescript, naming, errors, tests, security, performance, documentation, git
  decisions/      why: numbered architecture decision records
```

| Task involves                              | Read                                                                  |
| --------------------------------------------- | -------------------------------------------------------------------------- |
| A new module/endpoint                         | `docs/architecture/project-structure.md`, `docs/architecture/dependency-rules.md` |
| Tenant context, RLS policies                    | `docs/architecture/tenancy-and-rls.md`                                       |
| JWT, refresh tokens, roles/permissions           | `docs/architecture/tenancy-and-rls.md`, `docs/standards/security.md`           |
| Errors (401 vs 403, info leaks)                  | `docs/standards/errors.md`                                                    |
| Naming a function, file or module                | `docs/standards/naming.md`                                                    |
| Commit, branch or PR                             | `docs/standards/git.md`                                                        |
| Tests                                            | `docs/standards/tests.md`                                                      |
| Password hashing, tokens, RLS bypass risk         | `docs/standards/security.md`                                                   |

## Architecture (short version)

Modular NestJS, one module per concern. Full rules: `docs/architecture/`.

```txt
src/
  auth/            login, refresh, JWT issuance/validation, password hashing/reset
  organizations/   Organization CRUD
  memberships/     user <-> organization <-> role (the /members endpoints)
  invitations/     admin invites email -> membership on accept
  audit/           tenant-scoped audit trail (the RLS-protected business table)
  mail/            SMTP or console-logged links
  prisma/          PrismaService (auth plane) + TenantPrismaService (RLS plane)
  common/
    guards/        JwtAuthGuard, RolesGuard, PermissionsGuard
    decorators/    @Roles(), @RequirePermission(), @CurrentTenant(), @CurrentUser(), @Public()
    rbac/          role -> permission map
    filters/       Prisma exception filter
  main.ts

prisma/
  schema.prisma    RLS policies live in a migration, not just in Prisma's schema comments
```

- `JwtStrategy` is the only place that reads the JWT's tenant/role claims; controllers hand the tenant to services via `@CurrentTenant()`, and services trust that argument — they never re-parse the token.
- Every business table with tenant-scoped data has `ROW LEVEL SECURITY` enabled and a policy keyed on `current_setting('app.current_tenant')` — see [tenancy-and-rls.md](./docs/architecture/tenancy-and-rls.md). The tenant context is bound to a transaction (`TenantPrismaService.withTenant` runs `set_config(..., true)`), never to a pooled connection. Application-level filtering (`WHERE organizationId = ...`) is a UX/performance convenience, never the isolation guarantee.

## Never Do This

- Use `any`.
- Query a tenant-scoped table through a Prisma client/connection that never set `app.current_tenant` for the request — that's the one bug class this whole project exists to prevent. The only exception is the documented auth plane (`PrismaService`): register, login, refresh, password reset, invitation acceptance.
- Trust a client-supplied tenant id or role from anywhere but the verified JWT.
- Store a password in anything but a hashed (argon2) form.
- Reveal whether a resource exists to a caller who isn't authorized to see it (403 vs. 404 — see [errors.md](./docs/standards/errors.md)).
- Add a new dependency, abstraction, or file without climbing the ladder above first.
- Ship a change that makes any statement in `docs/` or this file false — update the affected doc in the same change.

## Validation

Run the smallest useful check for the change (full table: `docs/agents/validation.md`):

```bash
npm run typecheck
npm run lint
npm run test
```

Run `npm run test:e2e` (with `docker compose up -d`) for any change touching auth, guards, or RLS — a test that proves tenant A cannot read tenant B's data is the single most important test in this repo. Run `npm run build` when the change touches dependencies, module wiring, or public contracts.

## Before Reporting Done

Self-check against `docs/agents/review-checklist.md`, then summarize: what changed, files touched, checks run, anything skipped and why, any `Pending decision`.

## Safety

- Change only what is necessary; preserve unrelated user changes.
- Do not commit, push, or open PRs unless explicitly asked.
- Do not run destructive git operations without explicit instruction.
- Never disable or bypass an RLS policy "temporarily" to unblock a task — fix the tenant context instead.
