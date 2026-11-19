//! Currency helpers shared by billing and email formatting.

/// Stripe's zero-decimal currencies, whose amounts are already in whole units.
const ZERO_DECIMAL_CURRENCIES: &[&str] = &[
    "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "UGX", "VND", "VUV",
    "XAF", "XOF", "XPF",
];

/// Whether `currency` (an ISO code in any case) has no minor unit.
pub(crate) fn is_zero_decimal_currency(currency: &str) -> bool {
    ZERO_DECIMAL_CURRENCIES
        .iter()
        .any(|code| code.eq_ignore_ascii_case(currency))
}
