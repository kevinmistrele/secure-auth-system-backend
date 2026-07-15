# Git

- Branches: `claude/<topic>` for agent work, `feat/<topic>`, `fix/<topic>` otherwise.
- Commits: conventional prefix + imperative subject — `feat: add invitation revocation`, `fix: reject reused refresh tokens`. One logical change per commit; migrations and the code that needs them travel together.
- Never commit `.env`, `node_modules`, `dist`, or editor folders.
- A migration once pushed is immutable — fix forward with a new migration.
- PRs: describe what changed and which checks ran; call out anything security-relevant (new endpoint, new permission, RLS change) explicitly.
