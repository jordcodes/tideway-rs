# Organizations

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

## Core Types

- `OrganizationManager`: organization CRUD + owner bootstrap flow
- `MembershipManager`: membership operations and permission checks
- `InvitationManager`: invitation issuance and acceptance
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
