use std::fs;
use std::process::Command;

#[test]
fn test_backend_generates_webhook_idempotency_migrations() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = run_tideway(&[
        "backend",
        "b2c",
        "--name",
        "my_app",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migrations dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2c");

    assert!(
        migrations_dir.join("m008_create_billing_plans.rs").exists(),
        "expected m008_create_billing_plans.rs to be generated"
    );
    assert!(
        migrations_dir
            .join("m009_create_webhook_processed_events.rs")
            .exists(),
        "expected m009_create_webhook_processed_events.rs to be generated"
    );
    let billing_events_migration = migrations_dir.join("m010_create_billing_processed_events.rs");
    assert!(
        billing_events_migration.exists(),
        "expected m010_create_billing_processed_events.rs to be generated"
    );
    let billing_events =
        fs::read_to_string(billing_events_migration).expect("read billing event migration");
    assert!(billing_events.contains("billing_processed_events"));
    assert!(billing_events.contains("BillingProcessedEvents::EventId"));
    assert!(billing_events.contains("primary_key()"));

    let billing_plans = fs::read_to_string(migrations_dir.join("m008_create_billing_plans.rs"))
        .expect("read billing plans migration");
    assert!(billing_plans.contains("use serde_json::json;"));
    assert!(billing_plans.contains("json!({"));
    assert!(!billing_plans.contains(".default(\"{}\")"));

    let auth_mod = fs::read_to_string(output_dir.join("auth/mod.rs")).expect("read auth mod");
    assert!(auth_mod.contains("mod tests;"));
    let auth_tests = fs::read_to_string(output_dir.join("auth/tests.rs")).expect("read auth tests");
    assert!(auth_tests.contains("Migrator::up"));
    assert!(!auth_tests.contains("SimpleAuthProvider"));

    let lib_rs = fs::read_to_string(migrations_dir.join("lib.rs")).expect("read migration lib");
    assert!(
        lib_rs.contains("mod m009_create_webhook_processed_events;"),
        "expected m009 module declaration in lib.rs"
    );
    assert!(
        lib_rs.contains("Box::new(m009_create_webhook_processed_events::Migration),"),
        "expected m009 migration registration in lib.rs"
    );
    assert!(lib_rs.contains("mod m010_create_billing_processed_events;"));
    assert!(lib_rs.contains("Box::new(m010_create_billing_processed_events::Migration),"));
}

#[test]
fn test_backend_migration_lib_matches_generated_files_for_b2c_and_b2b() {
    assert_migration_lib_matches_generated_files("b2c");
    assert_migration_lib_matches_generated_files("b2b");
}

#[test]
fn test_b2b_backend_generates_hardened_invitations_without_affecting_b2c() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let b2b_src = temp_dir.path().join("b2b/src");
    let b2b_migrations = temp_dir.path().join("b2b/migration/src");
    let output = run_tideway(&[
        "backend",
        "b2b",
        "--output",
        b2b_src.to_str().expect("output dir utf8"),
        "--migrations-output",
        b2b_migrations.to_str().expect("migration dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2b");

    let invitations = fs::read_to_string(b2b_src.join("organizations/invitations.rs"))
        .expect("read invitation routes");
    assert!(invitations.contains("Sha256::digest(token.as_bytes())"));
    assert!(invitations.contains("claim.rows_affected != 1"));
    assert!(invitations.contains("ensure_invitee_matches(&invitation.email, &actor.user.email)"));
    assert!(invitations.contains("InvitationRateLimiter"));
    assert!(invitations.contains("Arc<dyn InvitationRateLimitProvider>"));
    assert!(invitations.contains("with_rate_limit_provider"));
    assert!(invitations.contains(".check_invitation_rate"));
    assert!(invitations.contains("/invitations/{invitation_id}/resend"));
    assert!(invitations.contains("resend_delivery_failure_restores_previous_token"));
    assert!(invitations.contains("expired_invitation_resend_rechecks_seat_capacity"));
    assert!(invitations.contains("expired_invitation_cannot_replace_a_newer_active_invitation"));
    assert!(
        b2b_migrations
            .join("m011_create_organization_invitations.rs")
            .exists()
    );

    let b2c_src = temp_dir.path().join("b2c/src");
    let b2c_migrations = temp_dir.path().join("b2c/migration/src");
    let output = run_tideway(&[
        "backend",
        "b2c",
        "--output",
        b2c_src.to_str().expect("output dir utf8"),
        "--migrations-output",
        b2c_migrations.to_str().expect("migration dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2c");
    assert!(!b2c_src.join("organizations/invitations.rs").exists());
    assert!(
        !b2c_migrations
            .join("m011_create_organization_invitations.rs")
            .exists()
    );
}

#[test]
fn test_b2b_backend_can_omit_optional_invitations() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");
    let output = run_tideway(&[
        "backend",
        "b2b",
        "--without-invitations",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migration dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2b --without-invitations");

    assert!(!output_dir.join("organizations/invitations.rs").exists());
    assert!(
        !output_dir
            .join("entities/organization_invitation.rs")
            .exists()
    );
    assert!(
        !migrations_dir
            .join("m011_create_organization_invitations.rs")
            .exists()
    );
    let main = fs::read_to_string(output_dir.join("main.rs")).expect("read main");
    assert!(!main.contains("OrganizationInvitationsModule"));
}

#[test]
fn test_organization_frontend_matches_invitation_api_contract() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("components");
    let output = run_tideway(&[
        "generate",
        "organizations",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
    ]);
    assert_success(&output, "tideway generate organizations");

    assert!(
        output_dir
            .join("organizations/AcceptInvitation.vue")
            .exists()
    );
    let composable =
        fs::read_to_string(output_dir.join("organizations/composables/useOrganization.ts"))
            .expect("read organization composable");
    assert!(composable.contains("async function acceptInvitation(token: string)"));
    assert!(composable.contains("'/invitations/accept', { token }"));
    assert!(composable.contains("async function resendInvitation("));
    assert!(composable.contains("/invitations/${invitationId}/resend"));

    let types = fs::read_to_string(output_dir.join("types/index.ts")).expect("read types");
    assert!(types.contains("organization_id: string"));
    assert!(types.contains("invited_by: string"));
    assert!(types.contains("'revoked'"));
    assert!(!types.contains("org_id: string"));
}

#[test]
fn test_b2c_checkout_uses_authenticated_user_email() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = run_tideway(&[
        "backend",
        "b2c",
        "--name",
        "my_app",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migrations dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2c");

    let routes =
        fs::read_to_string(output_dir.join("billing/routes.rs")).expect("read B2C billing routes");
    assert!(
        routes.contains(
            "let actor = authorize_billing_owner(&headers, &state, &body.user_id).await?;"
        )
    );
    assert!(routes.contains("id: actor.user.id.to_string()"));
    assert!(routes.contains("email: actor.user.email.clone()"));
    assert!(!routes.contains("email: \"\".to_string()"));
}

#[test]
fn test_backend_billing_routes_are_mounted_with_explicit_access_boundaries() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = run_tideway(&[
        "backend",
        "b2b",
        "--name",
        "my_app",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migrations dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2b");

    let main_rs = fs::read_to_string(output_dir.join("main.rs")).expect("read main.rs");
    assert!(main_rs.contains("use my_app::auth::AuthModule;"));
    assert!(!main_rs.contains("mod auth;"));
    assert!(main_rs.contains(".nest(\"/billing/public\", public_billing_routes())"));
    assert!(main_rs.contains(".nest(\"/billing\", authenticated_billing_routes())"));
    assert!(main_rs.contains(".nest(\"/billing/webhook\", billing_webhook_routes())"));
    assert!(main_rs.contains(".nest(\"/admin/billing\", admin_billing_routes())"));
    assert!(!main_rs.contains(".nest(\"/billing\", billing_routes())"));

    let billing_routes =
        fs::read_to_string(output_dir.join("billing/routes.rs")).expect("read billing routes");
    let billing_events =
        fs::read_to_string(output_dir.join("billing/events.rs")).expect("read billing events");
    assert!(billing_routes.contains("pub fn public_billing_routes()"));
    assert!(billing_routes.contains("pub fn authenticated_billing_routes()"));
    assert!(billing_routes.contains("pub fn billing_webhook_routes()"));
    assert!(billing_routes.contains("pub fn admin_billing_routes()"));
    assert!(billing_routes.contains("authorize_billing_owner"));
    assert!(billing_routes.contains("authorize_billing_member"));
    assert!(billing_routes.contains("require_platform_admin"));
    assert!(billing_routes.contains("billing_store.claim_event(&event.id)"));
    assert!(billing_routes.contains("billing_store.release_event_claim(&event.id)"));
    assert!(billing_routes.contains("deactivate_plans_with_price(state, price_id).await?"));
    assert!(billing_routes.contains(".with_event_sink(AppBillingEventSink)"));
    assert!(billing_events.contains("impl BillingEventSink for AppBillingEventSink"));
    assert!(billing_events.contains("event.event_id()"));
}

#[test]
fn test_backend_auth_uses_shared_guards_and_atomic_token_updates() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = run_tideway(&[
        "backend",
        "b2b",
        "--name",
        "my_app",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migrations dir utf8"),
    ]);
    assert_success(&output, "tideway backend b2b");

    let routes = fs::read_to_string(output_dir.join("auth/routes.rs")).expect("read auth routes");
    assert!(routes.contains("login_rate_limiter: LoginRateLimiter"));
    assert!(routes.contains("state.mfa_tokens.clone()"));
    assert!(routes.contains("ClientIpResolver::from_env(\"TRUSTED_PROXY_IPS\")"));
    assert!(routes.contains("state.client_ip_resolver.resolve(address.ip(), &headers)"));
    assert!(routes.contains("DbUserStore::from_transaction(transaction.clone())"));
    assert!(routes.contains("Arc::try_unwrap(transaction)"));

    let store = fs::read_to_string(output_dir.join("auth/store.rs")).expect("read auth store");
    assert!(store.contains("compare_and_swap_family_generation"));
    assert!(store.contains("update.rows_affected == 1"));
    assert!(store.contains("revoke_all_for_user(user_id)"));
}

fn run_tideway(args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tideway"));
    for arg in args {
        command.arg(arg);
    }
    command.output().expect("run tideway")
}

fn assert_success(output: &std::process::Output, label: &str) {
    assert!(
        output.status.success(),
        "{} failed.\nstdout:\n{}\nstderr:\n{}",
        label,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_migration_lib_matches_generated_files(preset: &str) {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let output_dir = temp_dir.path().join("src");
    let migrations_dir = temp_dir.path().join("migration/src");

    let output = run_tideway(&[
        "backend",
        preset,
        "--name",
        "my_app",
        "--output",
        output_dir.to_str().expect("output dir utf8"),
        "--migrations-output",
        migrations_dir.to_str().expect("migrations dir utf8"),
    ]);
    assert_success(&output, &format!("tideway backend {}", preset));

    let lib_rs = fs::read_to_string(migrations_dir.join("lib.rs")).expect("read migration lib");
    let migration_mods = parse_migration_mods(&lib_rs);
    assert!(
        !migration_mods.is_empty(),
        "expected migration modules in lib.rs for {}",
        preset
    );

    for module in migration_mods {
        let file_path = migrations_dir.join(format!("{}.rs", module));
        assert!(
            file_path.exists(),
            "missing migration file for module '{}' at {}",
            module,
            file_path.display()
        );
    }
}

fn parse_migration_mods(lib_rs: &str) -> Vec<String> {
    lib_rs
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("mod m") && line.ends_with(';'))
        .map(|line| {
            line.strip_prefix("mod ")
                .and_then(|rest| rest.strip_suffix(';'))
                .expect("valid mod line")
                .to_string()
        })
        .collect()
}
