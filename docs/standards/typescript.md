# TypeScript

- `strict` is on and stays on. `any` is banned (lint error) — use `unknown` and narrow.
- Types come from the source of truth: Prisma-generated types (`Role`, `Invitation`, `Prisma.TransactionClient`) instead of hand-written duplicates; derive (`Omit`, `Pick`, `typeof ... [number]`) instead of re-declaring.
- Public service methods declare explicit return types.
- DTO classes use `!` definite-assignment with `class-validator` decorators; validation is the constructor.
- No default exports; named exports only.
- Prefer `readonly` fields, `const`, and narrow unions (`'ADMIN' | 'MEMBER'`) over enums-of-strings when Prisma already provides the enum.
