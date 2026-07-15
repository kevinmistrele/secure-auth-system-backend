# ADR 0003 — Opaque rotating refresh tokens with reuse detection

## Context

Access tokens are short-lived (15 min) and carry tenant claims. Sessions need renewal without re-login, and stolen refresh tokens must be revocable — a JWT refresh token can't be revoked without a denylist, which is a database table anyway.

## Decision

Refresh tokens are opaque 48-byte randoms, stored **hashed** (SHA-256) with `userId`, `organizationId`, expiry and `revokedAt`. Every `/auth/refresh` revokes the presented token and issues a new pair (rotation). Presenting an already-revoked token is treated as theft: the user's entire active token family is revoked. Logout and password reset revoke open sessions. Each token is bound to one organization; switching tenants issues a fresh pair.

## Consequences

- DB hit per refresh — acceptable at this scale (indexed unique lookup).
- A leaked DB dump exposes no usable refresh tokens (hashed).
- Client must always persist the newest refresh token or the session dies — the frontend does this in its auth provider.
