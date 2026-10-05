use super::*;
use crate::TidewayError;

fn purchase(account: &str, amount: u64, key: &str) -> GrantCredits {
    GrantCredits {
        account_id: account.into(),
        credit_type: "sms".into(),
        amount,
        source: CreditSource::Purchased,
        expires_at: None,
        idempotency_key: key.into(),
        metadata: serde_json::json!({}),
    }
}

fn hold(amount: u64, key: &str) -> ReserveCredits {
    ReserveCredits {
        account_id: "org-1".into(),
        credit_type: "sms".into(),
        amount,
        idempotency_key: key.into(),
        order: ConsumptionOrder::AllowanceFirst,
        metadata: serde_json::json!({}),
    }
}

fn revoke(grant: &str, amount: RevocationAmount, key: &str) -> RevokeCredits {
    RevokeCredits {
        grant_idempotency_key: grant.into(),
        amount,
        idempotency_key: key.into(),
        metadata: serde_json::json!({"reason": "refund"}),
    }
}

pub(super) async fn assert_revocation(store: &impl CreditStore) {
    store
        .grant(&purchase("org-1", 100, "pi-1"), 10)
        .await
        .unwrap();
    let spent = store.reserve(&hold(30, "spent"), 1_000, 20).await.unwrap();
    store.commit("org-1", &spent.id, 20).await.unwrap();
    store.reserve(&hold(50, "held"), 25, 20).await.unwrap();

    let revoked = store
        .revoke(&revoke("pi-1", RevocationAmount::ALL, "refund-1"), 20)
        .await
        .unwrap()
        .expect("grant exists");
    assert_eq!(revoked.bucket.remaining_amount, 0);
    assert_eq!(
        (revoked.revoked_amount, revoked.unrecovered_amount),
        (100, 80)
    );
    let balance = store.balance("org-1", "sms", 20).await.unwrap();
    assert_eq!((balance.available, balance.reserved), (0, 50));
    // An expired hold on a revoked grant is not available before or after cleanup.
    assert_eq!(
        store.balance("org-1", "sms", 30).await.unwrap().available,
        0
    );

    let retried = store
        .revoke(&revoke("pi-1", RevocationAmount::ALL, "refund-1"), 21)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retried, revoked);

    assert_eq!(store.release_expired(30, 100).await.unwrap(), 1);
    assert_eq!(
        store.balance("org-1", "sms", 30).await.unwrap().available,
        0
    );
    let after_release = store
        .revoke(&revoke("pi-1", RevocationAmount::ALL, "refund-1"), 31)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_release.unrecovered_amount, 30);

    let revocations = store
        .history("org-1", "sms", CreditHistoryQuery::default())
        .await
        .unwrap()
        .into_iter()
        .filter(|entry| entry.kind == CreditTransactionKind::Revoke)
        .collect::<Vec<_>>();
    assert_eq!(revocations.len(), 1);
    assert_eq!(revocations[0].amount, 100);
    assert_eq!(revocations[0].idempotency_key, "refund-1");

    // Partial revocations are cumulative and round up.
    store
        .grant(&purchase("org-1", 10, "pi-2"), 40)
        .await
        .unwrap();
    let quarter = RevocationAmount::Fraction {
        numerator: 1,
        denominator: 4,
    };
    let partial = store
        .revoke(&revoke("pi-2", quarter, "refund-2"), 40)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (partial.revoked_amount, partial.bucket.remaining_amount),
        (3, 7)
    );
    store
        .revoke(
            &revoke("pi-2", RevocationAmount::Credits(2), "refund-old"),
            41,
        )
        .await
        .unwrap();
    assert_eq!(
        store.balance("org-1", "sms", 41).await.unwrap().available,
        7
    );
    let half = RevocationAmount::Fraction {
        numerator: 1,
        denominator: 2,
    };
    store
        .revoke(&revoke("pi-2", half, "refund-3"), 42)
        .await
        .unwrap();
    assert_eq!(
        store.balance("org-1", "sms", 42).await.unwrap().available,
        5
    );

    assert!(
        store
            .revoke(&revoke("pi-missing", RevocationAmount::ALL, "refund-4"), 50)
            .await
            .unwrap()
            .is_none()
    );

    store
        .grant(&purchase("org-2", 5, "shared"), 50)
        .await
        .unwrap();
    store
        .grant(&purchase("org-3", 5, "shared"), 50)
        .await
        .unwrap();
    assert!(matches!(
        store
            .revoke(&revoke("shared", RevocationAmount::ALL, "refund-5"), 50)
            .await,
        Err(TidewayError::Conflict(_))
    ));
}
