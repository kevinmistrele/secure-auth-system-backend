# Documentation

- Code comments state constraints the code can't show (why the auth plane exists, why `set_config(..., true)`), never narrate the next line.
- Every doc in `docs/` must stay true: a change that falsifies a statement updates the doc in the same commit — that rule is enforced by the review checklist.
- ADRs (`docs/decisions/`) record *why*: numbered, short (context → decision → consequences). Write one when choosing between real alternatives (new dependency, isolation strategy, token design); don't write one for following an existing pattern.
- README is for humans running the project: setup, endpoints, data model, the RLS story. AGENTS.md is for whoever writes code here.
