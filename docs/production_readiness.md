# Production Readiness

Use this checklist before exposing a generated Tideway application to internet traffic.

## Authentication

- Leave `ALLOW_PUBLIC_REGISTRATION=false` for private or invitation-only products. When enabled,
  confirm that `/auth/register` is intentionally present in both the router and OpenAPI document.
  For the generated Vue form, expose the UI separately with
  `VITE_ALLOW_PUBLIC_REGISTRATION=true`; never treat that frontend flag as an access control.
- Configure email verification and a working delivery provider before requiring verification.
- Keep separate limits for login, registration, refresh, password reset, and verification resend.
- Keep logout available during ordinary authentication throttling.
- In multi-replica deployments, use a shared gateway or distributed limiter rather than relying
  only on an in-process quota.

## Network Boundary

- Populate `TRUSTED_PROXY_IPS` only with the exact proxy addresses or CIDR ranges that may supply
  forwarded headers. Keep `TIDEWAY_RATE_LIMIT_TRUSTED_PROXIES` equal to it when the global
  per-IP limiter is enabled. Leave both empty for direct internet traffic.
- Enable a suitable global or per-IP production policy in addition to endpoint-specific auth
  limits.
- Store JWT, MFA, database, email, and billing secrets in the deployment secret manager.

## PostgreSQL Security Tests

PostgreSQL-backed generated presets include a CI PostgreSQL service and expose
`TEST_DATABASE_URL`. Point it only at a disposable test database: generated tests create isolated
schemas and intentionally leave application database lifecycle management outside the test
process. Keep at least these application-owned integration tests:

- a user cannot read or mutate a resource belonging to another organization;
- a member cannot perform an owner/admin-only operation;
- concurrent requests cannot bypass uniqueness, seat, invitation, or idempotency constraints;
- refresh-token rotation allows only one concurrent use of a token generation;
- migrations apply cleanly to a fresh PostgreSQL database.

SQLite remains useful for fast unit tests, but it does not reproduce PostgreSQL locking,
constraint, transaction-isolation, or type behavior. Security invariants that depend on those
semantics must run against PostgreSQL.

## Release Gate

Run the following before deployment:

```bash
tideway --json doctor --upgrade --deny-warnings
tideway doctor --deny-warnings
tideway migrate
cargo test --locked
```
