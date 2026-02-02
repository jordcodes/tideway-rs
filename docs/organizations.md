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
