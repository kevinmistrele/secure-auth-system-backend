# Errors

- **401 Unauthorized** — we don't know who you are: missing/invalid/expired token, bad credentials, dead refresh token. Message must not distinguish wrong-email from wrong-password.
- **403 Forbidden** — we know who you are and the answer is no: role/permission missing, acting on yourself/the owner in ways that are never allowed, switching to an org you're not in. Use 403 only when the caller was *allowed to know the resource exists*.
- **404 Not Found** — the resource doesn't exist *for this caller*. A member of tenant A probing tenant B's ids must get 404 (RLS already filters the row out, so this falls out naturally), never a 403 that confirms existence.
- **409 Conflict** — unique violations (email already registered, already a member). Mapped from Prisma P2002 by `PrismaExceptionFilter`.
- **400 Bad Request** — DTO validation failures (`class-validator`, global `ValidationPipe`).

Never include internal identifiers, SQL, or stack traces in a response body. Throw Nest's built-in `HttpException` subclasses from services; controllers don't catch.
