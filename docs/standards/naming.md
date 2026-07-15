# Naming

- Files: kebab-case with Nest suffixes — `invitations.service.ts`, `jwt-auth.guard.ts`, `current-tenant.decorator.ts`, `update-member-role.dto.ts`.
- Classes: `PascalCase` with the same suffix (`InvitationsService`); modules plural for collections (`memberships`), singular for capabilities (`mail`, `audit`).
- Methods: verb-first, from the caller's vocabulary — `listPending`, `switchTenant`, `withTenant`. Booleans read as predicates (`roleHasPermission`).
- Database: snake_case tables/columns via `@map`/`@@map`; Prisma models stay PascalCase.
- Permissions: `resource:action` (`invitations:create`). Audit actions: `resource.event` (`invitation.accept`).
- "Tenant" is the concept in code (`tenantId`, `app.current_tenant`); "Organization" is the domain object users see. Don't mix them in one API surface.
