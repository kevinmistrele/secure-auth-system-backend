# Performance

- Every RLS policy predicate must be index-backed: tenant-scoped tables index `organization_id` (see `@@index` in the schema). A new tenant-scoped table gets that index in the same migration as its policy.
- `withTenant` opens a transaction per call — batch the work of one request into one `withTenant`, don't call it per query in a loop.
- List endpoints cap results (`take: 100` on audit logs); add pagination before raising caps.
- Don't `include` relations you don't return; use `select` for user fields on member listings.
- argon2 hashing is the intended cost — never lower its parameters to speed up tests; tests share one hash per user instead.
