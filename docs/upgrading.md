# Upgrading Tideway Applications

Tideway upgrades should be small, reviewable changes. Update the framework and only the
dependencies or APIs required by that framework release; keep unrelated application cleanup in
separate commits.

## Recommended Workflow

1. Update the CLI so its checks target the current framework release:

   ```bash
   cargo install tideway-cli --locked
   ```

2. Run the read-only upgrade check from the application directory:

   ```bash
   tideway doctor --upgrade
   ```

   Use `--json` for CI or agent workflows. The check does not edit files or contact a registry. It
   compares the application with the framework version bundled into the installed CLI.

3. Change the Tideway version in `Cargo.toml`, then update only Tideway first:

   ```bash
   cargo update -p tideway --precise <version>
   cargo check --locked
   ```

4. Apply the specific compatibility changes reported by `doctor --upgrade` and this guide.

5. Run the application's complete test suite before committing:

   ```bash
   cargo test --locked
   ```

Avoid a broad `cargo update` during the framework upgrade. It makes failures harder to attribute
and mixes Tideway migration work with unrelated dependency changes.

## 0.7.13 to 0.7.23

Applications using the same surfaces as the API and SaaS presets may need these changes:

| Area | Required migration |
| --- | --- |
| Tideway | Set `tideway = "0.7.23"` and run `cargo update -p tideway --precise 0.7.23`. |
| Validation | If the app directly depends on `validator`, align it to `0.20`. A mismatch can surface as opaque Axum `Handler` trait errors. |
| Stripe | Tideway 0.7.23 billing selects async-stripe's `runtime-tokio-hyper` transport. A direct async-stripe dependency must select the same transport because async-stripe rejects multiple TLS implementations. |
| App context | Replace direct `context.database` field access with `context.database_opt()` or the appropriate public database accessor. |
| JWT issuing | Replace `JwtIssuerConfig::with_secret(...)` with `with_secure_secret(...)?`. Secrets must contain at least 32 bytes. |
| JWT verification | Replace `JwtVerifier::from_secret(...)` with `from_secret_checked(...)?`. |

The secure JWT constructor migration validates secret strength; it does not require changing token
audience or issuer policy. Treat policy changes as separate, explicitly reviewed auth work.

## Deployment Checks

- Confirm `JWT_SECRET` and any separate portal/auth secrets are at least 32 bytes before deploying.
- Expect `cargo check` to catch compile-time API migrations, but run integration tests for auth,
  billing, migrations, and generated routes.
- Commit the framework upgrade separately from security-audit cleanup and broad lockfile refreshes.

## Maintainer Contract

Before publishing a Tideway release:

- add release-specific notes here for any downstream edit;
- run `bash scripts/check_downstream_upgrade.sh`;
- keep `tideway doctor --upgrade` aligned with the versions and feature choices in the release;
- include the downstream upgrade result in the release checklist.
