# Security

- **Passwords**: argon2 (default parameters), never bcrypt-compare against plain text, never log or return a hash.
- **Access tokens**: JWT, 15 min, claims `{ sub, email, tenantId, role }`. Signed with `JWT_SECRET`; `JwtStrategy` is the single place claims are parsed.
- **Refresh tokens**: opaque 48-byte random values. Stored only as SHA-256 hashes. Rotated on every refresh; reusing a rotated token revokes the user's whole token family (theft signal). Logout and password reset revoke open sessions.
- **Reset/invitation tokens**: reset tokens are short-lived JWTs with a `purpose` claim; invitation tokens are opaque randoms stored hashed with a 7-day expiry.
- **Tenant identity**: only ever from the verified JWT. A client-supplied organization id is acceptable *only* to choose among the caller's own memberships (login, switch-tenant) — and is validated against the membership table.
- **RLS bypass risk**: the privileged connection (`PrismaService`) is restricted to the auth plane. Never "temporarily" route a tenant query through it — fix the tenant context instead. See `docs/architecture/tenancy-and-rls.md`.
- **Enumeration**: login returns the same 401 for unknown email and wrong password; password-reset requests always return success; cross-tenant probes see 404.
- **Secrets**: env only (`.env` is gitignored). The `app_user` dev password in the migration is dev-only — production must override `APP_DATABASE_URL` with real credentials.
