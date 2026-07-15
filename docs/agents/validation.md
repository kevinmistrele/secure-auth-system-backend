# Validation

Run the smallest check that proves the change works:

| Change | Minimum check |
| --- | --- |
| Docs only | none |
| Pure refactor, small logic change | `npm run typecheck && npm run lint && npm run test` |
| Guards, decorators, RBAC map | unit tests + `npm run test:e2e` |
| Auth flows, tenant context, RLS, migrations | `npm run test:e2e` (needs Postgres: `docker compose up -d && npx prisma migrate dev`) |
| Dependencies, module wiring, public contracts | all of the above + `npm run build` |

The e2e suite (`test/tenant-isolation.e2e-spec.ts`) is the contract: tenant isolation via API **and** raw RLS (unfiltered query, missing context, cross-tenant write). If your change makes any of those fail, the change is wrong — never the policy.

Environment for e2e: copy `.env.example` to `.env`; the suite truncates `users`/`organizations`, so point it at a disposable database.
