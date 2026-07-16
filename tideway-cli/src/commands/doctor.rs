//! Doctor command - diagnose Tideway project setup issues.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use colored::Colorize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::DoctorArgs;
use crate::commands::messaging::{
    DEV_FIX_ENV_COMMAND, GREENFIELD_NEW_APP_PRESET_API, NEW_APP_COMMAND,
    PRIMARY_PATH_REMINDER_CHAIN, RESOURCE_API_FLOW, SEA_ORM_MIGRATE_INIT_COMMAND,
    TIDEWAY_ADD_DATABASE_WIRE_COMMAND, TIDEWAY_ADD_OPENAPI_COMMAND,
    TIDEWAY_ADD_OPENAPI_WIRE_COMMAND, TIDEWAY_BACKEND_COMMAND, TIDEWAY_DEV_COMMAND,
    TIDEWAY_RESOURCE_WIRE_COMMAND,
};
use crate::database::validate_database_url as shared_validate_database_url;
use crate::{
    CommandRuntime, TIDEWAY_VERSION, print_info, print_success, print_warning, write_file,
};

const UPGRADE_GUIDE_URL: &str =
    "https://github.com/jordcodes/tideway-rs/blob/main/docs/upgrading.md";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorFindingLevel {
    Info,
    Fix,
    Warning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorFinding {
    pub level: DoctorFindingLevel,
    pub message: String,
    pub code: Option<&'static str>,
    pub affected_path: Option<String>,
    pub docs_url: Option<&'static str>,
}

#[derive(Debug, Default)]
pub struct DoctorReport {
    findings: Vec<DoctorFinding>,
}

impl DoctorReport {
    pub fn findings(&self) -> &[DoctorFinding] {
        &self.findings
    }

    pub fn info(&self) -> Vec<&str> {
        self.messages(DoctorFindingLevel::Info)
    }

    pub fn fixes(&self) -> Vec<&str> {
        self.messages(DoctorFindingLevel::Fix)
    }

    pub fn warnings(&self) -> Vec<&str> {
        self.messages(DoctorFindingLevel::Warning)
    }

    pub fn push_info(&mut self, message: impl Into<String>) {
        self.push(DoctorFindingLevel::Info, message);
    }

    pub fn push_fix(&mut self, message: impl Into<String>) {
        self.push(DoctorFindingLevel::Fix, message);
    }

    pub fn push_warning(&mut self, message: impl Into<String>) {
        self.push(DoctorFindingLevel::Warning, message);
    }

    fn push_upgrade_info(
        &mut self,
        code: &'static str,
        affected_path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.push_with_metadata(DoctorFindingLevel::Info, code, affected_path, message);
    }

    fn push_upgrade_warning(
        &mut self,
        code: &'static str,
        affected_path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.push_with_metadata(DoctorFindingLevel::Warning, code, affected_path, message);
    }

    fn messages(&self, level: DoctorFindingLevel) -> Vec<&str> {
        self.findings
            .iter()
            .filter(|finding| finding.level == level)
            .map(|finding| finding.message.as_str())
            .collect()
    }

    fn push(&mut self, level: DoctorFindingLevel, message: impl Into<String>) {
        self.findings.push(DoctorFinding {
            level,
            message: message.into(),
            code: None,
            affected_path: None,
            docs_url: None,
        });
    }

    fn push_with_metadata(
        &mut self,
        level: DoctorFindingLevel,
        code: &'static str,
        affected_path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.findings.push(DoctorFinding {
            level,
            message: message.into(),
            code: Some(code),
            affected_path: Some(affected_path.into()),
            docs_url: Some(UPGRADE_GUIDE_URL),
        });
    }
}

pub fn run(args: DoctorArgs) -> Result<()> {
    run_with_runtime(args, CommandRuntime::from_process_state())
}

pub fn run_with_runtime(args: DoctorArgs, runtime: CommandRuntime) -> Result<()> {
    runtime.install();

    if args.fix && args.upgrade {
        anyhow::bail!("--fix and --upgrade cannot be combined; upgrade checks are read-only");
    }

    let project_dir = PathBuf::from(args.path);
    let report = analyze_project_with_upgrade(&project_dir, args.fix, args.upgrade)?;
    let info = report.info();
    let fixes = report.fixes();
    let warnings = report.warnings();

    if !runtime.json_output() {
        println!(
            "\n{} {}\n",
            "tideway".cyan().bold(),
            "doctor report".blue().bold()
        );
    }

    if info.is_empty() && warnings.is_empty() {
        print_success("No issues found");
        print_info(PRIMARY_PATH_REMINDER_CHAIN);
        return Ok(());
    }

    if runtime.json_output() {
        for finding in report.findings() {
            print_finding_json(finding);
        }
    } else {
        for line in &info {
            print_info(line);
        }

        for line in &fixes {
            print_success(line);
        }

        if !warnings.is_empty() {
            println!();
            for warning in &warnings {
                print_warning(warning);
            }
        }
    }

    let summary = format!(
        "Doctor summary: {} info, {} fixes, {} warnings",
        info.len(),
        fixes.len(),
        warnings.len()
    );
    print_info(&summary);
    print_info(&format!(
        "Primary path reminder: for greenfield apps use {}; treat `add`/`init`/`backend` as advanced commands.",
        NEW_APP_COMMAND
    ));

    if args.deny_warnings && !warnings.is_empty() {
        anyhow::bail!(
            "Doctor found {} warning(s) and --deny-warnings was requested",
            warnings.len()
        );
    }

    Ok(())
}

fn print_finding_json(finding: &DoctorFinding) {
    let level = match finding.level {
        DoctorFindingLevel::Info => "info",
        DoctorFindingLevel::Fix => "success",
        DoctorFindingLevel::Warning => "warning",
    };
    let mut payload = json!({
        "level": level,
        "message": finding.message,
    });
    if let Some(code) = finding.code {
        payload["code"] = json!(code);
    }
    if let Some(path) = &finding.affected_path {
        payload["affected_path"] = json!(path);
    }
    if let Some(docs_url) = finding.docs_url {
        payload["docs_url"] = json!(docs_url);
    }
    println!("{payload}");
}

pub fn analyze_project(project_dir: &Path, fix: bool) -> Result<DoctorReport> {
    analyze_project_with_upgrade(project_dir, fix, false)
}

pub fn analyze_project_with_upgrade(
    project_dir: &Path,
    fix: bool,
    upgrade: bool,
) -> Result<DoctorReport> {
    let mut report = DoctorReport::default();

    let cargo_toml_path = project_dir.join("Cargo.toml");
    let cargo_toml = read_cargo_toml(&cargo_toml_path)?;
    let tideway_features = tideway_features(&cargo_toml);

    if upgrade {
        if !tideway_dependency_present(&cargo_toml) {
            report.push_upgrade_warning(
                "TW-UPGRADE-DEPENDENCY-MISSING",
                "Cargo.toml",
                "Cargo.toml is missing a tideway dependency",
            );
        }
        check_upgrade_readiness(project_dir, &cargo_toml, &tideway_features, &mut report);
        return Ok(report);
    }

    let src_dir = project_dir.join("src");
    let detected = detect_modules(&src_dir);

    if detected.is_empty() {
        report.push_info("No Tideway modules detected in src/".to_string());
    }

    for module in &detected {
        let feature = module_to_feature(module);
        if !tideway_features.contains(feature) {
            report.push_warning(format!(
                "Detected {} module but Tideway feature '{}' is not enabled in Cargo.toml",
                module, feature
            ));
        }
    }

    if !tideway_dependency_present(&cargo_toml) {
        report.push_warning("Cargo.toml is missing a tideway dependency".to_string());
    }

    if let Some(message) = validate_package_metadata(&cargo_toml) {
        report.push_info(message);
    }

    if !tideway_features.is_empty() && cargo_toml_path.exists() {
        report.push_info(format!(
            "Tideway features enabled: {}",
            tideway_features
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let env_file = project_dir.join(".env");
    let env_example_file = project_dir.join(".env.example");
    let mut env_vars = read_env_map(&env_file).unwrap_or_default();
    let mut env_example_vars = read_env_map(&env_example_file).unwrap_or_default();
    let project_name = project_name_from_cargo(&cargo_toml, project_dir);
    let database_backend = infer_database_backend(&cargo_toml);

    let needs_database = tideway_features.contains("database") || detected.contains("database");
    let needs_auth = tideway_features.contains("auth") || detected.contains("auth");
    let needs_mfa = tideway_features.contains("auth-mfa");
    let needs_billing = tideway_features.contains("billing") || detected.contains("billing");

    if fix {
        apply_env_fixes(
            &env_file,
            &env_example_file,
            &project_name,
            needs_database,
            database_backend,
            needs_auth,
            needs_mfa,
            needs_billing,
            &mut report,
        )?;
        env_vars = read_env_map(&env_file).unwrap_or_default();
        env_example_vars = read_env_map(&env_example_file).unwrap_or_default();
    }

    if needs_database {
        let db_value = check_env_var(
            "DATABASE_URL",
            &env_file,
            &env_example_file,
            &env_vars,
            &env_example_vars,
            &mut report,
        );
        if let Some(value) = db_value
            && let Some(message) = validate_database_url(&value)
        {
            report.push_warning(message);
        }
    }

    if needs_auth {
        let jwt_secret = check_env_var(
            "JWT_SECRET",
            &env_file,
            &env_example_file,
            &env_vars,
            &env_example_vars,
            &mut report,
        );
        if env_vars.contains_key("JWT_SECRET")
            && let Some(message) = jwt_secret.as_deref().and_then(validate_jwt_secret)
        {
            report.push_warning(message);
        }
    }

    if needs_mfa {
        let mfa_key = check_env_var(
            "MFA_ENCRYPTION_KEY",
            &env_file,
            &env_example_file,
            &env_vars,
            &env_example_vars,
            &mut report,
        );
        if env_vars.contains_key("MFA_ENCRYPTION_KEY")
            && let Some(message) = mfa_key.as_deref().and_then(validate_mfa_encryption_key)
        {
            report.push_warning(message);
        }
    }

    if needs_billing {
        for key in [
            "STRIPE_SECRET_KEY",
            "STRIPE_WEBHOOK_SECRET",
            "STRIPE_PRICE_ID",
        ] {
            check_env_var(
                key,
                &env_file,
                &env_example_file,
                &env_vars,
                &env_example_vars,
                &mut report,
            );
        }
    }

    if !has_log_config(&env_vars, &env_example_vars) {
        report.push_info(
            "No log level configured (set TIDEWAY_LOG_LEVEL or RUST_LOG for more output)"
                .to_string(),
        );
    }

    if !has_port_config(&env_vars, &env_example_vars) {
        report.push_info(
            "No port configured (set TIDEWAY_PORT or PORT for deploy environments)".to_string(),
        );
    }

    let main_contents = fs::read_to_string(src_dir.join("main.rs")).ok();

    if needs_auth {
        check_auth_capabilities(
            &src_dir,
            &tideway_features,
            &env_vars,
            main_contents.as_deref(),
            &mut report,
        );
    }

    if tideway_features.contains("openapi") {
        check_openapi_setup(&src_dir, main_contents.as_deref(), &mut report);
        check_openapi_doc_coverage(&src_dir, &mut report);
    }

    if needs_database {
        check_migration_setup(project_dir, &mut report);
        check_database_wiring(&src_dir, main_contents.as_deref(), &mut report);
        check_webhook_idempotency_setup(project_dir, &src_dir, fix, &mut report);
        check_migration_execution_hint(
            project_dir,
            &env_vars,
            &env_example_vars,
            main_contents.as_deref(),
            &mut report,
        );
    }

    Ok(report)
}

fn check_upgrade_readiness(
    project_dir: &Path,
    cargo_toml: &toml::Value,
    tideway_features: &BTreeSet<String>,
    report: &mut DoctorReport,
) {
    match dependency_version(cargo_toml, "tideway") {
        Some(version) if dependency_version_matches(version, TIDEWAY_VERSION) => report.push_upgrade_info(
            "TW-UPGRADE-VERSION-ALIGNED",
            "Cargo.toml",
            format!("Tideway dependency is aligned with this CLI ({TIDEWAY_VERSION})"),
        ),
        Some(version) => report.push_upgrade_warning(
            "TW-UPGRADE-VERSION-MISMATCH",
            "Cargo.toml",
            format!("Cargo.toml declares Tideway {version}; this CLI targets {TIDEWAY_VERSION}. Review {UPGRADE_GUIDE_URL}, set tideway = \"{TIDEWAY_VERSION}\", then run `cargo update -p tideway --precise {TIDEWAY_VERSION}`"),
        ),
        None if tideway_dependency_present(cargo_toml) => report.push_upgrade_info(
            "TW-UPGRADE-VERSION-UNPINNED",
            "Cargo.toml",
            "Tideway uses a path or workspace dependency; published-version alignment was not checked",
        ),
        None => {}
    }

    if tideway_features.contains("validation") {
        match dependency_version(cargo_toml, "validator") {
            Some(version) if !dependency_version_matches(version, "0.20") => report.push_upgrade_warning(
                "TW-UPGRADE-VALIDATOR-MISMATCH",
                "Cargo.toml",
                format!("Direct validator dependency is {version}, but Tideway {TIDEWAY_VERSION} uses validator 0.20; align it to avoid opaque Axum Handler errors"),
            ),
            Some(_) => report.push_upgrade_info(
                "TW-UPGRADE-VALIDATOR-ALIGNED",
                "Cargo.toml",
                "Direct validator dependency is aligned with Tideway (0.20)",
            ),
            None => {}
        }
    }

    let billing_enabled = tideway_features_enable_billing(tideway_features);
    if billing_enabled && let Some((dependency_name, features)) = async_stripe_features(cargo_toml)
    {
        let incompatible = [
            "runtime-tokio-hyper-rustls",
            "runtime-tokio-hyper-rustls-webpki",
        ]
        .iter()
        .filter(|feature| features.contains(**feature))
        .copied()
        .collect::<Vec<_>>();

        if incompatible.is_empty() {
            report.push_upgrade_info(
                "TW-UPGRADE-STRIPE-TLS-ALIGNED",
                "Cargo.toml",
                format!(
                    "Direct {dependency_name} TLS transport does not conflict with Tideway billing"
                ),
            );
        } else {
            report.push_upgrade_warning(
                "TW-UPGRADE-STRIPE-TLS-CONFLICT",
                "Cargo.toml",
                format!("Direct {dependency_name} enables {}, while Tideway {TIDEWAY_VERSION} billing uses runtime-tokio-hyper; async-stripe permits only one TLS implementation. Use runtime-tokio-hyper for the direct dependency", incompatible.join(", ")),
            );
        }
    }

    let src_dir = project_dir.join("src");
    if tideway_features.contains("billing-seaorm")
        || any_rs_file_contains(&src_dir, "SeaOrmBillingStore")
    {
        match billing_event_migration_status(project_dir) {
            BillingEventMigrationStatus::Ready => report.push_upgrade_info(
                "TW-UPGRADE-BILLING-MIGRATION-READY",
                "migration/src/",
                "billing_processed_events migration includes a primary-key event ID",
            ),
            BillingEventMigrationStatus::Missing => report.push_upgrade_warning(
                "TW-UPGRADE-BILLING-MIGRATION-MISSING",
                "migration/src/",
                "SeaOrmBillingStore requires a billing_processed_events migration with event_id as the primary key; add and run the 0.7.24 billing idempotency migration before deploying",
            ),
            BillingEventMigrationStatus::MissingPrimaryKey => report.push_upgrade_warning(
                "TW-UPGRADE-BILLING-MIGRATION-PRIMARY-KEY",
                "migration/src/",
                "A billing_processed_events migration was found, but doctor could not confirm event_id is its primary key; duplicate webhook claims are only atomic when the database enforces uniqueness",
            ),
        }
        if !billing_event_claim_lifecycle_ready(project_dir) {
            report.push_upgrade_warning(
                "TW-UPGRADE-BILLING-RECOVERABLE-CLAIMS",
                "migration/src/",
                "SeaOrmBillingStore requires status, claim_token, and claimed_at columns on billing_processed_events; add and run an application-owned additive migration before deploying this Tideway version",
            );
        }
    }

    let missing_claim_methods = custom_billing_store_missing_claim_methods(&src_dir);
    if billing_enabled && !missing_claim_methods.is_empty() {
        report.push_upgrade_warning(
            "TW-UPGRADE-BILLING-CLAIM-LIFECYCLE",
            "src/",
            format!(
                "Custom BillingStore implementation found without {} override(s); implement token-owned, expiring claims so abandoned work is retryable and an old worker cannot complete or release a newer claim",
                missing_claim_methods.join(", ")
            ),
        );
    }
    if billing_enabled && custom_billing_store_missing_subscription_cas(&src_dir) {
        report.push_upgrade_warning(
            "TW-UPGRADE-BILLING-SUBSCRIPTION-CAS",
            "src/",
            "Custom BillingStore implementation found without a compare_and_save_subscription override; implement it as one atomic conditional update so concurrent Stripe seat changes cannot overwrite newer subscription state",
        );
    }
    if any_rs_file_contains(&src_dir, "JwtIssuerConfig::with_secret(") {
        report.push_upgrade_warning(
            "TW-UPGRADE-JWT-ISSUER-SECRET",
            "src/",
            "Deprecated JwtIssuerConfig::with_secret found; migrate to with_secure_secret(...) and propagate its Result",
        );
    }
    if any_rs_file_contains(&src_dir, "JwtVerifier::from_secret(") {
        report.push_upgrade_warning(
            "TW-UPGRADE-JWT-VERIFIER-SECRET",
            "src/",
            "Deprecated JwtVerifier::from_secret found; migrate to from_secret_checked(...) and propagate its Result",
        );
    }
    let display_name_issues_tokens = any_rs_file_matches(&src_dir, |contents| {
        contents.contains("JwtIssuerConfig::with_secure_secret")
            && (contents.contains("&app_config.app_name") || contents.contains("&config.app_name"))
    });
    let package_name_verifies_tokens = any_rs_file_matches(&src_dir, |contents| {
        contents.contains(".with_issuer(env!(\"CARGO_PKG_NAME\"))")
    });
    if display_name_issues_tokens && package_name_verifies_tokens {
        report.push_upgrade_warning(
            "TW-UPGRADE-JWT-IDENTITY-DRIFT",
            "src/",
            "JWT issuance uses the display-facing app name while a verifier expects CARGO_PKG_NAME; define stable JWT_ISSUER/JWT_AUDIENCE values, configure issuance and verification from them together, and test login followed by a protected route",
        );
    }
    if any_rs_file_contains(&src_dir, ".database.is_some()") {
        report.push_upgrade_warning(
            "TW-UPGRADE-APP-CONTEXT-DATABASE",
            "src/",
            "Direct AppContext.database access found; use the public database_opt() accessor",
        );
    }
}

fn tideway_features_enable_billing(features: &BTreeSet<String>) -> bool {
    features.iter().any(|feature| {
        matches!(
            feature.as_str(),
            "billing" | "billing-seaorm" | "organizations-billing"
        )
    })
}

fn custom_billing_store_missing_claim_methods(src_dir: &Path) -> Vec<&'static str> {
    let missing_acquire = any_rs_file_matches(src_dir, |contents| {
        uncommented_line_contains(contents, "BillingStore for")
            && !uncommented_line_contains(contents, "fn acquire_event_claim")
    });
    let missing_complete = any_rs_file_matches(src_dir, |contents| {
        uncommented_line_contains(contents, "BillingStore for")
            && !uncommented_line_contains(contents, "fn complete_event_claim")
    });
    let missing_release = any_rs_file_matches(src_dir, |contents| {
        uncommented_line_contains(contents, "BillingStore for")
            && !uncommented_line_contains(contents, "fn release_owned_event_claim")
    });

    let mut missing = Vec::new();
    if missing_acquire {
        missing.push("acquire_event_claim");
    }
    if missing_complete {
        missing.push("complete_event_claim");
    }
    if missing_release {
        missing.push("release_owned_event_claim");
    }
    missing
}

fn billing_event_claim_lifecycle_ready(project_dir: &Path) -> bool {
    migration_sources_contain(
        project_dir,
        "billing_processed_events",
        "BillingProcessedEvents",
    )
}

fn custom_billing_store_missing_subscription_cas(src_dir: &Path) -> bool {
    any_rs_file_matches(src_dir, |contents| {
        uncommented_line_contains(contents, "BillingStore for")
            && !uncommented_line_contains(contents, "fn compare_and_save_subscription")
    })
}

fn uncommented_line_contains(contents: &str, needle: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with("//") && trimmed.contains(needle)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BillingEventMigrationStatus {
    Ready,
    Missing,
    MissingPrimaryKey,
}

fn billing_event_migration_status(project_dir: &Path) -> BillingEventMigrationStatus {
    let root = project_dir.join("migration").join("src");
    let mut stack = vec![root];
    let mut found_table = false;

    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            if let Ok(entries) = fs::read_dir(&path) {
                stack.extend(entries.flatten().map(|entry| entry.path()));
            }
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        if !contents.contains("billing_processed_events") {
            continue;
        }

        found_table = true;
        if billing_event_id_is_primary_key(&contents) {
            return BillingEventMigrationStatus::Ready;
        }
    }

    if found_table {
        BillingEventMigrationStatus::MissingPrimaryKey
    } else {
        BillingEventMigrationStatus::Missing
    }
}

fn billing_event_id_is_primary_key(contents: &str) -> bool {
    let sea_orm_definition_is_primary =
        contents.split("ColumnDef::new").skip(1).any(|definition| {
            definition.contains("BillingProcessedEvents::EventId")
                && definition.contains("primary_key()")
        });
    if sea_orm_definition_is_primary {
        return true;
    }

    // Support raw SQL migrations conservatively: the constraint must appear in the same
    // comma-delimited column definition as event_id, not merely elsewhere in the file.
    contents
        .to_ascii_lowercase()
        .split(',')
        .any(|definition| definition.contains("event_id") && definition.contains("primary key"))
}

fn dependency_version<'a>(cargo_toml: &'a toml::Value, name: &str) -> Option<&'a str> {
    let dependency = cargo_toml.get("dependencies")?.get(name)?;
    match dependency {
        toml::Value::String(version) => Some(version.as_str()),
        toml::Value::Table(table) => table.get("version")?.as_str(),
        _ => None,
    }
}

fn dependency_version_matches(version: &str, expected: &str) -> bool {
    let normalized = version.trim().trim_start_matches(['=', '^', '~', ' ']);
    normalized == expected
        || normalized
            .strip_prefix(expected)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn async_stripe_features(cargo_toml: &toml::Value) -> Option<(&str, BTreeSet<String>)> {
    let dependencies = cargo_toml.get("dependencies")?.as_table()?;
    for (name, dependency) in dependencies {
        let Some(table) = dependency.as_table() else {
            continue;
        };
        let package = table.get("package").and_then(toml::Value::as_str);
        if name != "async-stripe" && package != Some("async-stripe") {
            continue;
        }

        let features = table
            .get("features")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(str::to_string)
            .collect();
        return Some((name.as_str(), features));
    }
    None
}

fn check_auth_capabilities(
    src_dir: &Path,
    tideway_features: &BTreeSet<String>,
    env_vars: &BTreeMap<String, String>,
    main_contents: Option<&str>,
    report: &mut DoctorReport,
) {
    let store = fs::read_to_string(src_dir.join("auth/store.rs")).unwrap_or_default();
    let email_verification_required = env_vars
        .get("REQUIRE_EMAIL_VERIFICATION")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));

    if email_verification_required
        && !main_contents
            .unwrap_or_default()
            .contains(".with_email_delivery(")
    {
        report.push_warning(
            "REQUIRE_EMAIL_VERIFICATION=true, but AuthModule is not configured with_email_delivery(...); configure a Mailer before enabling verification"
                .to_string(),
        );
    }

    if tideway_features.contains("auth-mfa")
        && store.contains("async fn has_mfa_enabled")
        && store.contains("Ok(false)")
    {
        report.push_warning(
            "The auth-mfa feature is enabled, but the generated user store still reports MFA as disabled; implement MFA secret and backup-code persistence before advertising MFA"
                .to_string(),
        );
    }
}

fn read_cargo_toml(path: &Path) -> Result<toml::Value> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    contents
        .parse::<toml::Value>()
        .with_context(|| format!("Failed to parse {}", path.display()))
}

fn tideway_features(cargo_toml: &toml::Value) -> BTreeSet<String> {
    let mut features = BTreeSet::new();

    let deps = cargo_toml.get("dependencies");
    let tideway = deps.and_then(|d| d.get("tideway"));

    match tideway {
        Some(toml::Value::Table(table)) => {
            if let Some(toml::Value::Array(values)) = table.get("features") {
                for value in values {
                    if let Some(feature) = value.as_str() {
                        features.insert(feature.to_string());
                    }
                }
            }
        }
        Some(toml::Value::String(_)) => {
            // No features listed; keep empty.
        }
        _ => {}
    }

    features
}

fn tideway_dependency_present(cargo_toml: &toml::Value) -> bool {
    cargo_toml
        .get("dependencies")
        .and_then(|deps| deps.get("tideway"))
        .is_some()
}

fn detect_modules(src_dir: &Path) -> BTreeSet<String> {
    let mut modules = BTreeSet::new();

    let module_dirs = [
        "auth",
        "billing",
        "organizations",
        "admin",
        "jobs",
        "cache",
        "session",
        "email",
        "websocket",
        "metrics",
        "validation",
        "openapi",
    ];

    for module in module_dirs {
        let path = src_dir.join(module);
        if path.is_dir() {
            modules.insert(module.to_string());
        }
    }

    modules
}

fn module_to_feature(module: &str) -> &str {
    match module {
        "session" => "sessions",
        other => other,
    }
}

fn read_env_map(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(parse_env_map(&contents))
}

fn parse_env_map(contents: &str) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                vars.insert(key.to_string(), value.to_string());
            }
        }
    }
    vars
}

fn check_env_var(
    key: &str,
    env_path: &Path,
    env_example_path: &Path,
    env_vars: &BTreeMap<String, String>,
    env_example_vars: &BTreeMap<String, String>,
    report: &mut DoctorReport,
) -> Option<String> {
    if let Some(value) = env_vars.get(key) {
        return Some(value.clone());
    }

    if env_example_vars.contains_key(key) {
        report.push_warning(format!(
            "{} missing in .env (found in .env.example) - copy .env.example and fill values (or use the primary flow: {})",
            key,
            DEV_FIX_ENV_COMMAND
        ));
        return env_example_vars.get(key).cloned();
    }

    if env_path.exists() || env_example_path.exists() {
        report.push_warning(format!("{} missing in .env and .env.example", key));
        return None;
    }

    report.push_warning(format!(
        "{} missing - create .env.example (and .env) for local setup (for greenfield apps, prefer {})",
        key,
        NEW_APP_COMMAND
    ));
    None
}

fn validate_database_url(value: &str) -> Option<String> {
    shared_validate_database_url(value)
        .err()
        .map(|error| error.to_string())
}

fn validate_jwt_secret(value: &str) -> Option<String> {
    let value = value.trim();
    if matches!(
        value,
        "your-super-secret-jwt-key-change-in-production" | "replace-with-at-least-32-random-bytes"
    ) {
        return Some(
            "JWT_SECRET uses a public placeholder; replace it with at least 32 random bytes"
                .to_string(),
        );
    }
    if value.len() < 32 {
        return Some("JWT_SECRET must contain at least 32 bytes of random data".to_string());
    }
    None
}

fn validate_mfa_encryption_key(value: &str) -> Option<String> {
    match STANDARD.decode(value.trim()) {
        Ok(key) if key.len() == 32 => None,
        _ => Some(
            "MFA_ENCRYPTION_KEY must be independent base64 encoding exactly 32 random bytes (generate with `openssl rand -base64 32`)"
                .to_string(),
        ),
    }
}

fn has_log_config(
    env_vars: &BTreeMap<String, String>,
    env_example_vars: &BTreeMap<String, String>,
) -> bool {
    env_vars.contains_key("TIDEWAY_LOG_LEVEL")
        || env_vars.contains_key("RUST_LOG")
        || env_example_vars.contains_key("TIDEWAY_LOG_LEVEL")
        || env_example_vars.contains_key("RUST_LOG")
}

fn has_port_config(
    env_vars: &BTreeMap<String, String>,
    env_example_vars: &BTreeMap<String, String>,
) -> bool {
    env_vars.contains_key("TIDEWAY_PORT")
        || env_vars.contains_key("PORT")
        || env_example_vars.contains_key("TIDEWAY_PORT")
        || env_example_vars.contains_key("PORT")
}

fn validate_package_metadata(cargo_toml: &toml::Value) -> Option<String> {
    let package = cargo_toml.get("package")?.as_table()?;
    let missing = ["description", "license", "repository"]
        .iter()
        .filter(|key| !package.contains_key(**key))
        .cloned()
        .collect::<Vec<_>>();

    if missing.is_empty() {
        return None;
    }

    Some(format!("Package metadata missing: {}", missing.join(", ")))
}

fn env_example_template(
    project_name: &str,
    needs_database: bool,
    database_backend: &str,
    needs_auth: bool,
    needs_mfa: bool,
    needs_billing: bool,
) -> Option<Vec<String>> {
    let mut lines = Vec::new();
    if needs_database || needs_auth || needs_billing {
        lines.push("# Server".to_string());
        lines.push("TIDEWAY_HOST=0.0.0.0".to_string());
        lines.push("TIDEWAY_PORT=8000".to_string());
        if needs_billing {
            lines.push("APP_URL=http://localhost:8000".to_string());
        }
        lines.push(String::new());
    }

    if needs_database {
        lines.push("# Database".to_string());
        let database_url = match database_backend {
            "sqlite" => format!("DATABASE_URL=sqlite:./{}.db?mode=rwc", project_name),
            _ => format!(
                "DATABASE_URL=postgres://postgres:postgres@localhost:5432/{}",
                project_name
            ),
        };
        lines.push(database_url);
        lines.push(String::new());
    }

    if needs_auth {
        lines.push("# Auth".to_string());
        lines.push("JWT_SECRET=replace-with-at-least-32-random-bytes".to_string());
        lines.push(format!("JWT_ISSUER={}", project_name));
        lines.push(format!("JWT_AUDIENCE={}", project_name));
        if needs_mfa {
            lines.push("MFA_ENCRYPTION_KEY=".to_string());
        }
        lines.push(String::new());
    }

    if needs_billing {
        lines.push("# Billing".to_string());
        lines.push("STRIPE_SECRET_KEY=sk_test_tideway_local_only_000000".to_string());
        lines.push("STRIPE_WEBHOOK_SECRET=whsec_replace_me".to_string());
        lines.push("STRIPE_PRICE_ID=price_replace_me".to_string());
        lines.push(String::new());
    }

    if lines.is_empty() { None } else { Some(lines) }
}

fn project_name_from_cargo(cargo_toml: &toml::Value, project_dir: &Path) -> String {
    if let Some(name) = cargo_toml
        .get("package")
        .and_then(|pkg| pkg.get("name"))
        .and_then(|value| value.as_str())
    {
        return name.replace('-', "_");
    }

    project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my_app")
        .replace('-', "_")
}
fn write_env_example(path: &Path, lines: &[String]) -> Result<()> {
    let contents = lines.join("\n");
    write_file(path, &contents).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_env_fixes(
    env_file: &Path,
    env_example_file: &Path,
    project_name: &str,
    needs_database: bool,
    database_backend: &str,
    needs_auth: bool,
    needs_mfa: bool,
    needs_billing: bool,
    report: &mut DoctorReport,
) -> Result<()> {
    let Some(lines) = env_example_template(
        project_name,
        needs_database,
        database_backend,
        needs_auth,
        needs_mfa,
        needs_billing,
    ) else {
        return Ok(());
    };
    let expected_vars = parse_env_map(&lines.join("\n"));

    if !env_example_file.exists() {
        write_env_example(env_example_file, &lines)?;
        report.push_fix("Created .env.example".to_string());
    } else {
        let existing = fs::read_to_string(env_example_file).with_context(|| {
            format!(
                "Failed to read {} while applying doctor fixes",
                env_example_file.display()
            )
        })?;
        let existing_vars = parse_env_map(&existing);
        let mut missing_keys = Vec::new();
        for key in expected_vars.keys() {
            if !existing_vars.contains_key(key) {
                missing_keys.push(key.clone());
            }
        }

        if !missing_keys.is_empty() {
            let mut merged = existing.trim_end().to_string();
            merged.push_str("\n\n# Added by tideway doctor --fix\n");
            for key in &missing_keys {
                if let Some(value) = expected_vars.get(key) {
                    merged.push_str(&format!("{}={}\n", key, value));
                }
            }
            write_file(env_example_file, &merged).with_context(|| {
                format!(
                    "Failed to write {} while applying doctor fixes",
                    env_example_file.display()
                )
            })?;
            report.push_fix(format!(
                "Updated .env.example with missing keys: {}",
                missing_keys.join(", ")
            ));
        }
    }

    if !env_file.exists() && env_example_file.exists() {
        let source = fs::read_to_string(env_example_file).with_context(|| {
            format!(
                "Failed to read {} while creating .env",
                env_example_file.display()
            )
        })?;
        write_file(env_file, &source)
            .with_context(|| format!("Failed to write {}", env_file.display()))?;
        report.push_fix("Created .env from .env.example".to_string());
    }

    Ok(())
}

fn infer_database_backend(cargo_toml: &toml::Value) -> &'static str {
    if dependency_has_feature(cargo_toml, "sea-orm", "sqlx-sqlite")
        || dependency_has_feature(cargo_toml, "sea-orm-migration", "sqlx-sqlite")
    {
        "sqlite"
    } else {
        "postgres"
    }
}

fn dependency_has_feature(cargo_toml: &toml::Value, dependency: &str, feature: &str) -> bool {
    cargo_toml
        .get("dependencies")
        .and_then(|deps| deps.get(dependency))
        .and_then(|dep| dep.as_table())
        .and_then(|table| table.get("features"))
        .and_then(|features| features.as_array())
        .is_some_and(|features| features.iter().any(|value| value.as_str() == Some(feature)))
}

fn check_openapi_setup(src_dir: &Path, main_contents: Option<&str>, report: &mut DoctorReport) {
    let openapi_docs = src_dir.join("openapi_docs.rs");
    if !openapi_docs.exists() {
        report.push_warning(format!(
            "OpenAPI is enabled but src/openapi_docs.rs is missing (advanced fix: run {}; greenfield path: {})",
            TIDEWAY_ADD_OPENAPI_COMMAND,
            GREENFIELD_NEW_APP_PRESET_API
        ));
    }

    let main_rs = src_dir.join("main.rs");
    if let Some(contents) = main_contents {
        let has_module = contents.contains("mod openapi_docs;");
        let has_router =
            contents.contains("openapi_merge_module") || contents.contains("create_openapi_router");
        if !has_module || !has_router {
            report.push_warning(format!(
                "OpenAPI is enabled but main.rs is not wired (advanced fix: run {}; greenfield path: {})",
                TIDEWAY_ADD_OPENAPI_WIRE_COMMAND,
                GREENFIELD_NEW_APP_PRESET_API
            ));
        }
    } else if main_rs.exists() {
        report.push_warning("Failed to read src/main.rs for OpenAPI wiring check".to_string());
    }
}

fn check_openapi_doc_coverage(src_dir: &Path, report: &mut DoctorReport) {
    let openapi_docs = src_dir.join("openapi_docs.rs");
    if !openapi_docs.exists() {
        return;
    }

    let Ok(docs_contents) = fs::read_to_string(&openapi_docs) else {
        report.push_warning("Failed to read src/openapi_docs.rs".to_string());
        return;
    };

    let paths_block = extract_openapi_paths(&docs_contents);
    if paths_block.is_empty() {
        report.push_warning(
            format!(
                "OpenAPI docs file has no paths() entries (add routes or run {}; primary path reminder: {})",
                TIDEWAY_RESOURCE_WIRE_COMMAND,
                RESOURCE_API_FLOW
            ),
        );
        return;
    }

    let routes_dir = src_dir.join("routes");
    if !routes_dir.exists() {
        return;
    }

    let mut missing = Vec::new();
    if let Ok(entries) = fs::read_dir(&routes_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let file_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if file_name == "mod" {
                continue;
            }
            if let Ok(contents) = fs::read_to_string(&path)
                && !contents.contains("cfg_attr(feature = \"openapi\"")
            {
                continue;
            }

            let expected_prefix = format!("crate::routes::{}::", file_name);
            if !paths_block
                .iter()
                .any(|path| path.starts_with(&expected_prefix))
            {
                missing.push(file_name.to_string());
            }
        }
    }

    if !missing.is_empty() {
        report.push_warning(format!(
            "OpenAPI docs missing routes for: {} (run {} to add; this is part of the primary flow)",
            TIDEWAY_RESOURCE_WIRE_COMMAND,
            missing.join(", ")
        ));
    }
}

fn extract_openapi_paths(contents: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut in_paths = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("paths(") {
            in_paths = true;
            continue;
        }
        if in_paths && trimmed.starts_with(')') {
            break;
        }
        if in_paths {
            let trimmed = trimmed.trim_end_matches(',');
            if !trimmed.is_empty() {
                lines.push(trimmed.to_string());
            }
        }
    }
    lines
}

fn check_migration_setup(project_dir: &Path, report: &mut DoctorReport) {
    let migration_lib = project_dir.join("migration").join("src").join("lib.rs");
    if !migration_lib.exists() {
        report.push_warning(format!(
            "Missing migration/src/lib.rs (advanced fix: run {} or {}; greenfield path: {})",
            SEA_ORM_MIGRATE_INIT_COMMAND, TIDEWAY_BACKEND_COMMAND, GREENFIELD_NEW_APP_PRESET_API
        ));
    }
}

fn check_database_wiring(src_dir: &Path, main_contents: Option<&str>, report: &mut DoctorReport) {
    let routes_dir = src_dir.join("routes");
    if !routes_dir.exists() {
        return;
    }

    let mut has_db_routes = false;
    if let Ok(entries) = fs::read_dir(&routes_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            if let Ok(contents) = fs::read_to_string(&path)
                && (contents.contains("sea_orm_connection()")
                    || contents.contains("Entity::find")
                    || contents.contains("ActiveModel"))
            {
                has_db_routes = true;
                break;
            }
        }
    }

    if !has_db_routes {
        return;
    }

    if let Some(contents) = main_contents {
        if !contents.contains("with_database(") {
            report.push_warning(
                format!(
                    "DB-backed routes detected but AppContext is not wired (advanced fix: run {}; primary path for new resources: {})",
                    TIDEWAY_ADD_DATABASE_WIRE_COMMAND,
                    RESOURCE_API_FLOW
                ),
            );
        }
    } else if src_dir.join("main.rs").exists() {
        report.push_warning("Failed to read src/main.rs for database wiring check".to_string());
    }
}

fn check_migration_execution_hint(
    project_dir: &Path,
    env_vars: &BTreeMap<String, String>,
    env_example_vars: &BTreeMap<String, String>,
    main_contents: Option<&str>,
    report: &mut DoctorReport,
) {
    let migration_lib = project_dir.join("migration").join("src").join("lib.rs");
    if !migration_lib.exists() {
        return;
    }

    let has_auto_migrate = env_vars.contains_key("DATABASE_AUTO_MIGRATE")
        || env_example_vars.contains_key("DATABASE_AUTO_MIGRATE");
    let has_migration_call = main_contents
        .map(|contents| {
            contents.contains("run_migrations(")
                || contents.contains("run_migrations_now(")
                || contents.contains("Migrator::up(")
        })
        .unwrap_or(false);

    if !has_auto_migrate && !has_migration_call {
        report.push_info(
            format!(
                "Migrations detected but not auto-run (set DATABASE_AUTO_MIGRATE=true, call run_migrations, or use {}; primary local run command is {})",
                TIDEWAY_DEV_COMMAND,
                DEV_FIX_ENV_COMMAND
            ),
        );
    }
}

fn check_webhook_idempotency_setup(
    project_dir: &Path,
    src_dir: &Path,
    fix: bool,
    report: &mut DoctorReport,
) {
    if !project_uses_database_webhook_idempotency(src_dir) {
        return;
    }

    if has_webhook_idempotency_migration(project_dir) {
        report.push_info(
            "Webhook DB idempotency detected and migration marker found (webhook_processed_events)"
                .to_string(),
        );
        if !webhook_claim_lifecycle_ready(project_dir) {
            report.push_warning(
                "DatabaseIdempotencyStore requires status, claim_token, and claimed_at columns on webhook_processed_events; add and run an application-owned additive migration before deploying"
                    .to_string(),
            );
        }
        return;
    }

    report.push_warning(
        "DatabaseIdempotencyStore detected, but webhook_processed_events migration marker is missing (add migration e.g. m009_create_webhook_processed_events.rs and register it in migration/src/lib.rs)".to_string(),
    );

    if fix {
        report.push_fix(
            "Webhook idempotency migration TODO: create migration/src/m009_create_webhook_processed_events.rs (or equivalent) that creates `webhook_processed_events(event_id PRIMARY KEY, processed_at TIMESTAMPTZ NOT NULL)` and register it in migration/src/lib.rs".to_string(),
        );
    }
}

fn project_uses_database_webhook_idempotency(src_dir: &Path) -> bool {
    any_rs_file_contains(src_dir, "DatabaseIdempotencyStore")
}

fn has_webhook_idempotency_migration(project_dir: &Path) -> bool {
    let migration_src = project_dir.join("migration").join("src");
    if !migration_src.exists() {
        return false;
    }

    // Accept either explicit lib registration or table marker in migration files.
    let migration_marker = "webhook_processed_events";

    let lib_rs = migration_src.join("lib.rs");
    if lib_rs.exists()
        && fs::read_to_string(&lib_rs)
            .map(|s| s.contains(migration_marker))
            .unwrap_or(false)
    {
        return true;
    }

    any_rs_file_contains(&migration_src, migration_marker)
}

fn webhook_claim_lifecycle_ready(project_dir: &Path) -> bool {
    migration_sources_contain(
        project_dir,
        "webhook_processed_events",
        "WebhookProcessedEvents",
    )
}

fn migration_sources_contain(project_dir: &Path, raw_table: &str, iden_table: &str) -> bool {
    let migration_src = project_dir.join("migration").join("src");
    let Ok(entries) = fs::read_dir(migration_src) else {
        return false;
    };
    entries.flatten().any(|entry| {
        fs::read_to_string(entry.path()).is_ok_and(|contents| {
            (contents.contains(raw_table) || contents.contains(iden_table))
                && (contents.contains("claim_token") || contents.contains("ClaimToken"))
                && (contents.contains("claimed_at") || contents.contains("ClaimedAt"))
                && (contents.contains("status") || contents.contains("Status"))
        })
    })
}

fn any_rs_file_contains(root: &Path, needle: &str) -> bool {
    any_rs_file_matches(root, |contents| contents.contains(needle))
}

fn any_rs_file_matches(root: &Path, predicate: impl Fn(&str) -> bool) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        if fs::read_to_string(&path)
            .map(|contents| predicate(&contents))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}
