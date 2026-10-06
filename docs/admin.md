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

## Generated Admin Endpoints

The `saas` preset (and `tideway backend b2c|b2b`) generates `src/admin/routes.rs`, guarded by
`RequestActor::require_admin`. Its data comes from the app's own tables:

- `mfa_enabled` on users is `true` only when the user has `mfa_enabled` set *and* an enrolled
  TOTP secret, matching the auth store's `has_mfa_enabled`. Apps generated without `auth-mfa`
  always report `false`.
- `GET /admin/stats` includes billing fields only when the app was generated with billing:
  - `active_subscriptions` counts `billing_subscriptions` rows with status `active` or
    `trialing`.
  - `mrr_cents` / `mrr_currency` sum `billing_plans.price_cents` over subscriptions with status
    `active`. Yearly plans count as price ÷ 12, one-time plans are excluded, and trials are
    excluded because they are not paying yet.
- `subscription_status` on organizations is the status of the `billing_subscriptions` row whose
  `billable_id` is the organization ID, or `null` when there is none. The list endpoint loads
  statuses for the whole page in one query.
- Paginated responses echo the `page` and `per_page` actually used (`page` ≥ 1,
  `per_page` clamped to 1–100).

### When MRR is omitted

`mrr_cents` and `mrr_currency` are left out of the response, and `mrr_unavailable_reason` explains
why, when the billing tables can't produce an accurate number:

- An active subscription references a plan ID that has no `billing_plans` row. Plans configured
  only in code (`Plans::builder()` in `main.rs`) are not in that table, so add a matching
  `billing_plans` row for each plan you sell.
- An active subscription has `extra_seats > 0`. Seat counts are stored but seat *prices* are not,
  so seat revenue can't be computed.
- Active plans use more than one currency.

## Related Modules

- `auth`: identity, claims, and secure session/token handling
- `organizations`: tenant-aware membership and role boundaries
- `billing`: subscription/entitlement checks for admin tooling
