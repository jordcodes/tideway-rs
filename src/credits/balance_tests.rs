use super::*;

pub(super) async fn assert_read_only_balance(store: &impl CreditStore) {
    for (account, credit_type, source, amount, expires_at, key) in [
        (
            "org-1",
            "sms",
            CreditSource::Allowance,
            100,
            Some(40),
            "allowance",
        ),
        (
            "org-1",
            "sms",
            CreditSource::Purchased,
            50,
            None,
            "purchase",
        ),
        (
            "org-2",
            "sms",
            CreditSource::Purchased,
            500,
            None,
            "other-account",
        ),
        (
            "org-1",
            "email",
            CreditSource::Purchased,
            500,
            None,
            "other-type",
        ),
    ] {
        store
            .grant(
                &GrantCredits {
                    account_id: account.into(),
                    credit_type: credit_type.into(),
                    source,
                    amount,
                    expires_at,
                    idempotency_key: key.into(),
                    metadata: serde_json::json!({}),
                },
                10,
            )
            .await
            .unwrap();
    }
    for (amount, expires_at, key) in [(120, 30, "expired"), (10, 100, "active")] {
        store
            .reserve(
                &ReserveCredits {
                    account_id: "org-1".into(),
                    credit_type: "sms".into(),
                    amount,
                    idempotency_key: key.into(),
                    order: ConsumptionOrder::AllowanceFirst,
                    metadata: serde_json::json!({}),
                },
                expires_at,
                20,
            )
            .await
            .unwrap();
    }
    let before_expiry = store.balance("org-1", "sms", 29).await.unwrap();
    assert_eq!((before_expiry.available, before_expiry.reserved), (20, 130));
    let history = store
        .history("org-1", "sms", CreditHistoryQuery::default())
        .await
        .unwrap();
    for now in [30, 30, 40] {
        let balance = store.balance("org-1", "sms", now).await.unwrap();
        let allowance = if now < 40 { 100 } else { 0 };
        assert_eq!(balance.available, allowance + 40);
        assert_eq!(balance.reserved, 10);
        assert_eq!(
            balance.by_source,
            vec![
                SourceBalance {
                    source: CreditSource::Allowance,
                    available: allowance
                },
                SourceBalance {
                    source: CreditSource::Promotional,
                    available: 0
                },
                SourceBalance {
                    source: CreditSource::Purchased,
                    available: 40
                },
            ]
        );
        assert_eq!(
            store
                .history("org-1", "sms", CreditHistoryQuery::default())
                .await
                .unwrap(),
            history
        );
    }
    assert_eq!(
        store.balance("missing", "sms", 40).await.unwrap().available,
        0
    );
    assert_eq!(store.release_expired(40, 100).await.unwrap(), 1);
    let balance = store.balance("org-1", "sms", 40).await.unwrap();
    assert_eq!((balance.available, balance.reserved), (40, 10));
    assert_eq!(store.release_expired(40, 100).await.unwrap(), 0);
}
