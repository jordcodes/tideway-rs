# Organizations

> **Invitation-token upgrade:** SeaORM organization stores now persist SHA-256 invitation-token
> digests and atomically claim pending invitations before redemption. Existing plaintext pending
> invitations cannot be redeemed after upgrading; revoke or delete them and issue replacements.
> The database column may retain its existing name and width because the digest is a 64-character
> hexadecimal string.

`OrganizationManager::create` uses a compensating delete if owner-membership creation fails.
Custom database stores requiring strict isolation should override
`OrganizationStore::create_with_rollback` with transaction-aware persistence; the default contract
surfaces cleanup failures but cannot make two independent store implementations transactional.
When both stores are Tideway's built-in `SeaOrmOrgStore`, use
`OrganizationManager::create_atomic` to create the organization and initial owner membership in one
database transaction.

The `organizations` module provides multi-tenant B2B primitives:

- organization lifecycle (create, update, archive)
- memberships and role-based permissions
- invitations with optional rate limiting
- optional seat checks and billing integration
- optional SeaORM-backed storage

## Feature Flags

- `organizations`: core module
- `organizations-seaorm`: SeaORM storage adapters
- `organizations-billing`: seat checks via billing module
- `test-organizations`: in-memory test stores

## CLI Support

For focused backend scaffolding in an existing org-aware DB-backed auth project:

```bash
tideway add organizations --wire --db
```

This generates organization routes, SeaORM entities, and organization migrations without adding billing or admin scaffolding.
It expects the organizations-aware auth/user contract already to exist (`RequestActor` organization helpers, `user.organization_id`, and registered user migrations).

For a lightweight organization-shaped CRUD resource instead of the full organizations module:

```bash
tideway resource organization --profile tenant
tideway resource project --profile owned
```

For frontend-only Vue organization helpers:

```bash
tideway generate organizations --with-views
```

The full SaaS preset still generates auth, billing, organizations, and admin together:

```bash
tideway new my_app --preset saas
```

New SaaS/B2B scaffolds also include application-owned invitation routes, an invitation entity, and
an additive migration. The generated flow hashes bearer tokens before persistence, requires the
accepting account's normalized email to match the invitee, restricts invitation creation and
revocation to organization owners/admins, rate limits issuance, and atomically changes a token from
`pending` to `processing` before creating membership. Raw tokens are delivered only through the
configured `EmailService`.

Invitations are included by default on the batteries-included path. Omit them when another service
owns membership onboarding:

```bash
tideway new my_app --preset saas --without-invitations
tideway backend b2b --without-invitations
```

The generated backend reserves billing seats for pending invitations and rechecks capacity during
acceptance. Issuance and membership creation lock the organization row, preventing concurrent
requests from creating duplicate active invitations or consuming the same final seat.

Owners and admins can resend a pending invitation with
`POST /organizations/{org_id}/invitations/{invitation_id}/resend`. Resending is organization-scoped
and uses the same per-organization and per-actor rate limits as initial delivery, plus a short
delivery cooldown. It rotates the bearer token, invalidates the previous link, and refreshes the
expiry. Resending an expired invitation rechecks billing seat capacity because it creates a new
active seat reservation, and it is rejected when a newer active invitation already exists for the
same email. If delivery fails, the generated handler conditionally restores the previous token and
expiry rather than leaving an undisclosed replacement token active. The original `created_at`
timestamp is preserved across resends.

### Acceptance workflow

The emailed link opens `${APP_URL}/invitations/accept?token=...`. If you generate the optional Vue
organization components, mount `AcceptInvitation.vue` at `/invitations/accept`; its composable sends
the authenticated `POST /invitations/accept` request. The accepting developer must be signed in
with the same normalized email address that received the invitation. If your login or registration
flow redirects elsewhere, preserve the full acceptance URL as the post-authentication return URL.
The backend never accepts the token through a GET request.

### Invitation rate limiting

Generated applications use `InvitationRateLimiter` with `InvitationRateLimitConfig::default()`.
This in-memory token bucket allows a one-window burst and replenishes the configured allowance
evenly across the window. It requires no infrastructure and is the recommended default for a
single API process.

The default limiter is process-local: counters reset when the process restarts and are not shared
between replicas. This does not affect authorization, tenant isolation, invitation atomicity, or
billing seat enforcement; it only changes the anti-spam allowance. Railway and similar platforms
[load balance multi-replica services across independent processes](https://docs.railway.com/deployments/scaling),
so switch to a shared provider before horizontally scaling the API.

`OrganizationInvitationsModule` accepts any asynchronous `InvitationRateLimitProvider` while
retaining the in-memory provider out of the box:

```rust,ignore
use std::sync::Arc;
use tideway::organizations::InvitationRateLimitProvider;

let invitations = OrganizationInvitationsModule::new(
    db,
    jwt_secret,
    email_service,
    seat_checker,
)
.with_rate_limit_provider(Arc::new(redis_invitation_limiter));
```

A shared implementation should atomically check and update both the organization and actor quotas,
set expiry on its keys, and return `InvitationRateLimitExceeded` with an accurate retry delay.
Redis is not contacted or required unless the application explicitly constructs such a provider.
This keeps the default deployment simple while allowing multi-replica applications to share limits.

This is a greenfield scaffold, not an upgrade operation. `tideway add organizations` and
`tideway doctor --upgrade` do not inject invitation files or migrations into an established
application.

## Existing and Custom Organization Models

Organization entities, routes, roles, and migrations become application-owned when generated.
Applications with an existing organization or invitation model should keep it and adopt the
security properties above with focused edits. Do not run `tideway backend b2b --force` or copy the
new migration over an existing `organization_invitations` table.

For a custom persistent `InvitationStore`:

- persist a one-way digest of each raw bearer token and hash lookup input the same way;
- implement `claim_pending_by_token` as one conditional `pending` to `processing` update;
- implement `release_claim` so failed membership creation can be retried safely;
- make membership uniqueness a database constraint on organization and user;
- compare the authenticated account's normalized email with the invitation email;
- scope list/revoke operations by organization and return not-found for cross-organization IDs;
- rotate tokens on resend, rate limit delivery, and recheck seats when reactivating an expired invite;
- never grant the owner role through a normal invitation;
- avoid returning or logging token digests in API responses.

If an application currently stores raw pending tokens, plan that migration explicitly. Either
revoke and reissue outstanding invitations, or transform every stored raw token to its digest in a
reviewed data migration before deploying code that hashes lookup input. Test an outstanding token
against a production-like copy before rollout. The migration can keep a legacy column named
`token`; renaming it to `token_hash` is clearer but not required for correctness.

## Core Types

- `OrganizationManager`: organization CRUD + owner bootstrap flow
- `MembershipManager`: membership operations and permission checks
- `InvitationManager`: invitation issuance and acceptance
- `InvitationRateLimiter`: zero-configuration, process-local invitation rate limiter
- `InvitationRateLimitProvider`: asynchronous extension point for shared rate-limit backends
- `SeatChecker`: plug-in interface for seat limit checks

## Minimal Wiring

```rust
use tideway::organizations::{OrganizationConfig, OrganizationManager, UnlimitedSeats};

let manager = OrganizationManager::new(
    org_store,
    membership_store,
    UnlimitedSeats,
    OrganizationConfig::default(),
);
```

For JWT org-context extraction and permission guards, use:

- `organizations::auth::OrgStoreLayer`
- `organizations::auth::RequireOrgMembership`
- `organizations::auth::RequirePermission`

## Billing Integration

When both `organizations` and `billing` features are enabled, you can use
`BillingSeatChecker` to enforce plan seat limits during membership operations.

## Notes

- The module is trait-first: you define domain models and storage.
- Use `test-organizations` for fast in-memory integration tests.
