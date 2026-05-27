//! Spend action-binding header and step.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use pasta_curves::Fp;
use ragu::{Header, Index, Step, Suffix};

use super::spendable::SpendableHeader;
use crate::{
    constants::NOTE_VALUE_MAX,
    entropy::ActionRandomizer,
    keys::{PaymentKey, ProofAuthorizingKey, public},
    note::{self, CommitmentTrapdoor, Note, Nullifier, NullifierTrapdoor, Value},
    primitives::{Anchor, effect},
    value,
};

/// Header binding an action to its spendable lineage.
///
/// Carries `cv`, `rk`, the lineage's `present_nf`, the pool `anchor`, and the
/// note commitment `cm`; the nullifier pair is completed and published at
/// [`SpendStamp`](super::stamp::SpendStamp).
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    /// `(cv, rk, present_nf, anchor, cm)`. `cv`/`rk` are derived at
    /// [`SpendBind`]; `present_nf`, `anchor`, and `cm` thread from the
    /// spendable lineage that [`SpendBind`] consumed.
    type Data = (
        value::Commitment,
        public::ActionVerificationKey,
        Nullifier,
        Anchor,
        note::Commitment,
    );

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 5);
        let cv_bytes: [u8; 32] = data.0.into();
        let rk_bytes: [u8; 32] = data.1.into();
        out.extend_from_slice(&cv_bytes);
        out.extend_from_slice(&rk_bytes);
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out.extend_from_slice(&Fp::from(data.4).to_repr());
        out
    }
}

/// Binds an action to its spendable lineage's note.
///
/// Witnesses the note preimage (`pk`, `value`, `rcm`, `psi`), `pak`, and the
/// action fields (`rcv`, `alpha`); checks `cm == spendable.cm` (so `cv` commits
/// to the proven-minted value) and threads `present_nf`, `anchor`, and `cm`
/// onto the output. The live pair is completed at
/// [`SpendStamp`](super::stamp::SpendStamp).
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendHeader;
    type Right = ();
    type Witness<'source> = (
        (PaymentKey, Value, CommitmentTrapdoor, NullifierTrapdoor),
        value::CommitmentTrapdoor,
        ActionRandomizer<effect::Spend>,
        ProofAuthorizingKey,
    );

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        ((pk, value, rcm, psi), rcv, alpha, pak): Self::Witness<'source>,
        (present_nf, anchor, spendable_cm): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if u64::from(value) == 0 {
            return Err(ragu::Error("SpendBind: zero-value note"));
        }
        if u64::from(value) > NOTE_VALUE_MAX {
            return Err(ragu::Error("SpendBind: note value exceeds maximum"));
        }
        if pk.0 != pak.derive_payment_key().0 {
            return Err(ragu::Error("SpendBind: pak not related to note"));
        }
        let cm = Note {
            pk,
            value,
            psi,
            rcm,
        }
        .commitment();

        if spendable_cm != cm {
            return Err(ragu::Error(
                "SpendBind: note does not match the spendable lineage",
            ));
        }

        let cv = rcv.commit(i64::from(value));
        let rk = pak.ak.derive_action_public(&alpha);

        Ok(((cv, rk, present_nf, anchor, cm), ()))
    }
}
