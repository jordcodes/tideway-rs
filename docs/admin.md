# Admin

The `admin` module is for platform-level operations across tenants/users.

It provides shared admin-facing traits and types so applications can implement:

- user and organization listing/search
- account review and moderation workflows
- platform audit/reporting screens
- privileged support tooling (for example, controlled impersonation flows)

## Feature Flag

- `admin`: enables admin module exports

## Design

`admin` is intentionally lightweight and trait-driven. The framework does not
impose one storage schema or UI contract; applications provide their own
repositories/services and wire admin routes as needed.

## Typical Usage

1. Implement admin storage/service traits in your app layer.
2. Expose admin route modules guarded by your auth/role policy.
3. Reuse Tideway auth and organization primitives for permission checks.

## Related Modules

- `auth`: identity, claims, and secure session/token handling
- `organizations`: tenant-aware membership and role boundaries
- `billing`: subscription/entitlement checks for admin tooling
