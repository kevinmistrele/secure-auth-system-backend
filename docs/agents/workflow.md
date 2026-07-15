# Workflow

1. **Understand** — read the request, the code you're about to change, and its neighbors. Check the [Documentation Map](../../AGENTS.md#documentation-map) for the docs that govern the area.
2. **Shrink** — climb the ladder in `AGENTS.md`. Prefer reusing an existing guard/decorator/`withTenant` pattern over new abstractions. If something isn't needed, don't build it; say so in one line.
3. **Implement** — smallest reviewable diff. Follow `docs/standards/`. Tenant-scoped data goes through `TenantPrismaService.withTenant`; new tenant-scoped tables get RLS policies in the same migration.
4. **Validate** — run the smallest sufficient check (`docs/agents/validation.md`). Auth/guard/RLS changes always get `npm run test:e2e`.
5. **Self-review** — walk `docs/agents/review-checklist.md`.
6. **Report** — what changed, files touched, checks run, anything skipped and why, any `Pending decision`.
