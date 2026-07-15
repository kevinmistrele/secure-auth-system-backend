# Dependency Rules

Direction of allowed imports:

```
common  ←  (everything)          common depends on nothing but Nest + @prisma/client
prisma  ←  feature modules       feature modules depend on prisma services, never vice versa
mail    ←  auth, invitations
audit   ←  feature modules       audit is global; it must never import a feature module
auth    ←  invitations           invitations reuses AuthService.createSession
```

Rules:

- Feature modules never import each other's **services** except the explicitly allowed `invitations → auth` edge (session issuance after accepting an invite).
- `common/` must stay framework-level: no business logic, no Prisma queries.
- Only `auth/` (and the invitation-accept flow) may use `PrismaService` for tenant-scoped tables; everything else uses `TenantPrismaService.withTenant` — see [tenancy-and-rls.md](./tenancy-and-rls.md).
- Adding a new module? It gets its own folder, module file, and — if tenant-scoped — RLS policies in a migration in the same change.
