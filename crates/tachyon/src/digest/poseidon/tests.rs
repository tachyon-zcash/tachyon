use alloc::collections::BTreeSet;

use super::*;

#[test]
fn domains_are_distinct() {
    let domains = [
        FEE_BLIND_DOMAIN,
        FEE_DIGEST_DOMAIN,
        ACTION_DIGEST_DOMAIN,
        PAYMENT_KEY_DOMAIN,
        NOTE_COMMITMENT_DOMAIN,
        PAD_COMMITMENT_DOMAIN,
        NULLIFIER_MASTER_DOMAIN,
        SPEND_ALPHA_DOMAIN,
        OUTPUT_ALPHA_DOMAIN,
        NULLIFIER_DOMAIN,
        ANCHOR_STAMP_DOMAIN,
        QR_BUCKET_DOMAIN,
        EVIDENCE_NODE_DOMAIN,
        ANCHOR_EPOCH_DOMAIN,
    ];
    assert_eq!(BTreeSet::from(domains).len(), domains.len());
}
