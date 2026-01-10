//! Templates command - list available templates.

use anyhow::Result;
use colored::Colorize;

pub fn run() -> Result<()> {
    println!("\n{}\n", "Available Templates".cyan().bold());

    println!("{}", "Auth Module:".yellow());
    println!("  - LoginForm.vue        Email/password login with MFA support");
    println!("  - RegisterForm.vue     User + organization registration");
    println!("  - ForgotPassword.vue   Request password reset");
    println!("  - ResetPassword.vue    Complete password reset");
    println!("  - MfaVerify.vue        MFA code verification");
    println!("  - useAuth.ts           Auth composable");

    println!("\n{}", "Billing Module:".yellow());
    println!("  - SubscriptionStatus.vue    Current plan and trial info");
    println!("  - CheckoutButton.vue        Redirect to Stripe Checkout");
    println!("  - BillingPortalButton.vue   Redirect to Stripe Portal");
    println!("  - InvoiceHistory.vue        List past invoices");
    println!("  - PlanSelector.vue          Display available plans");
    println!("  - useBilling.ts             Billing composable");

    println!("\n{}", "Organizations Module:".yellow());
    println!("  - OrgSwitcher.vue      Switch between organizations");
    println!("  - OrgSettings.vue      Edit organization details");
    println!("  - MemberList.vue       List members with roles");
    println!("  - InviteMember.vue     Send email invitations");
    println!("  - useOrganization.ts   Organization composable");

    println!("\n{}", "Shared:".yellow());
    println!("  - types/index.ts       TypeScript types for API");
    println!("  - useApi.ts            Base API composable");

    println!("\n{}", "Styling Options:".cyan());
    println!("  --style shadcn     {} shadcn-vue components", "(default)".dimmed());
    println!("  --style tailwind   Plain Tailwind CSS classes");
    println!("  --style unstyled   Minimal HTML, no styling");

    println!("\n{}", "Usage:".cyan());
    println!("  tideway generate auth --style shadcn");
    println!("  tideway generate billing --output ./src/components");
    println!("  tideway generate all --framework vue");

    println!();

    Ok(())
}
