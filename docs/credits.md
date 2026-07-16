# Credits and allowances

Tideway's optional credits module provides a durable integer ledger for product units such as SMS
sends, emails, API calls, or AI credits. It is not a money wallet: credits are not transferable or
cash-redeemable, and the application still decides what an operation costs and when it succeeded.

## Add it to an application

For an existing SeaORM Tideway application:

```bash
tideway add credits
tideway migrate
```

The command enables `credits` and `credits-seaorm`, creates and registers a new ledger migration,
and ensures the migration crate enables SeaORM's `with-json` feature. It starts at
`m013_create_credit_ledger.rs` when that number is available and otherwise uses the next migration
number. It never renames, renumbers, or overwrites application migration history, including with
`--force`. Rerunning the command detects the existing ledger migration and remains idempotent. For
a new custom scaffold, selecting
`credits-seaorm` also creates and registers the schema. To use Stripe top-ups, additionally enable
`credits-stripe`.

```toml
tideway = { version = "0.7", features = ["credits-seaorm", "credits-stripe"] }
```

```rust
use tideway::credits::{CreditManager, SeaOrmCreditStore};

let credits = CreditManager::new(SeaOrmCreditStore::new(db.clone()));
```

Use an authenticated account or organization ID as `account_id`. Never accept an arbitrary account
ID from a request body without checking that the current actor belongs to that account.

## Grant a billing-period allowance

Granting is idempotent within an account and credit type. A subscription-period identifier is a
good key, so repeated Stripe lifecycle events cannot double-grant the allowance.

```rust
use tideway::credits::{CreditSource, GrantCredits};

credits.grant(GrantCredits {
    account_id: organization.id.to_string(),
    credit_type: "sms".into(),
    amount: 100,
    source: CreditSource::Allowance,
    expires_at: Some(subscription.current_period_end as i64),
    idempotency_key: format!(
        "subscription:{}:period:{}",
        subscription.id,
        subscription.current_period_start,
    ),
    metadata: serde_json::json!({ "plan_id": subscription.plan_id }),
}).await?;
```

Use `expires_at: None` for rollover or persistent grants. Purchased top-up credits are persistent by
default. The standard consumption order spends expiring allowance, then promotional credits, then
purchased credits.

## Reserve, perform, then commit

Reserve before calling an external provider. Commit only when the application considers the
operation successful; release on a normal failure.

```rust
use tideway::credits::ReserveCredits;

let reservation = credits.reserve(ReserveCredits {
    account_id: organization.id.to_string(),
    credit_type: "sms".into(),
    amount: 1,
    idempotency_key: format!("sms-send:{message_id}"),
    order: Default::default(),
    metadata: serde_json::json!({ "message_id": message_id }),
}).await?;

match sms_provider.send(message).await {
    Ok(receipt) => {
        credits.commit(&organization.id.to_string(), &reservation.id).await?;
        Ok(receipt)
    }
    Err(error) => {
        credits.release(&organization.id.to_string(), &reservation.id).await?;
        Err(error)
    }
}
```

Reservations expire after 15 minutes by default, so a terminated process cannot hold credits
forever. Change this with `CreditManager::with_reservation_ttl`. Grant, reserve, commit, and release
are idempotent. The SeaORM store uses transactions and conditional updates to prevent concurrent
overspending.

`balance` returns available and currently reserved units, broken down by source. `history` returns
the append-only audit ledger with bounded pagination.

Tideway deliberately does not generate public balance or history routes. Tenant authorization is
application-specific, and accepting `account_id` as an unverified URL or query parameter would make
cross-organization disclosure too easy. In an API handler, derive the account from the verified
actor, then call `balance` or `history`; expose only the metadata fields appropriate for your
product.

## Stripe prepaid top-ups

Define packs in server configuration. Clients choose a pack ID, never a price or credit quantity.

```rust
use tideway::billing::CheckoutConfig;
use tideway::credits::{
    CreditTopUpCatalog, CreditTopUpCheckoutManager, CreditTopUpPack,
};

let packs = CreditTopUpCatalog::new([CreditTopUpPack {
    id: "sms_100".into(),
    stripe_price_id: "price_...".into(),
    credit_type: "sms".into(),
    amount: 100,
}])?;

let top_ups = CreditTopUpCheckoutManager::new(
    stripe.clone(),
    packs.clone(),
    CheckoutConfig::new().allowed_redirect_domains(["app.example.com"]),
);
```

Attach `CreditTopUpEventSink` to the existing billing webhook handler:

```rust
use tideway::credits::CreditTopUpEventSink;

let top_up_sink = CreditTopUpEventSink::new(credits.clone(), packs);
let webhook = WebhookHandler::new(billing_store, webhook_secret, plans)
    .with_event_sink(top_up_sink);
```

The sink fulfils only Tideway-created `credit_top_up` sessions in Stripe `payment` mode whose
`payment_status` is `paid` or `no_payment_required`. Delayed payment methods are handled by
`checkout.session.async_payment_succeeded`. The signed event ID is the grant idempotency key. If the
application already has a billing event sink, compose it with `top_up_sink.with_next(existing_sink)`.

The application remains responsible for authorizing checkout creation, obtaining the Stripe
customer linked to that account, provider delivery, product wording, and deciding what counts as a
successful billable operation.

## Operational notes

- Run `release_expired` from periodic maintenance if an application has long stretches without
  balance or reservation requests. Normal balance and reservation operations also clean up a
  bounded batch of expired holds for that account and credit type; they never sweep other tenants
  or process an unlimited backlog in the request path.
- Treat pack IDs as immutable versions. If price, credit type, or amount changes, create a new pack
  ID and retain the old definition while its webhook deliveries may still be retried. Removing a
  pack early fails fulfilment safely rather than granting an unverified amount.
- Treat credit transaction metadata as operational context, not a place for secrets or message
  contents.
- For refunds or chargebacks, grant policy is application-specific. Use a stable compensating
  operation in application code; Tideway does not silently remove already-consumed credits.
