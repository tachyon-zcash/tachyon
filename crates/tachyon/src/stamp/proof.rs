//! Tachyon proofs via Ragu PCD.
//!
//! Tachyon uses **Ragu PCD** (Proof-Carrying Data) for proof generation and
//! aggregation. A single Ragu proof per aggregate covers all actions across
//! multiple bundles.
//!
//! ## Verification
//!
//! The header is not transmitted on the wire. The verifier reconstructs the PCD
//! header from public data according to consensus rules.
//!
//! 1. Recompute `action_acc` from the bundle's actions
//! 2. Recompute `tachygram_acc` from the listed tachygrams
//! 3. Construct the PCD header (`action_acc`, `tachygram_acc`, `anchor`)
//! 4. Call Ragu `verify(Pcd { proof, data: header })`
//!
//! A successful verification with a reconstructed header demonstrates that
//! consensus rules were followed.
//!
//! ## Proving
//!
//! The prover supplies an [`ActionPrivate`] per action, containing private
//! inputs that the circuit checks against the public action and tachygram.

extern crate alloc;

use alloc::vec::Vec;
use core::{marker::PhantomData, ops::Neg as _};

use ff::PrimeField as _;
pub use mock_ragu::Proof;
use mock_ragu::{self, Header, Index, Step, Suffix};
use pasta_curves::{EqAffine, Fp, group::GroupEncoding as _};

use crate::{
    action::Action,
    entropy::{ActionRandomizer, Witness},
    keys::{ProofAuthorizingKey, private::ActionSigningKey},
    note::Note,
    primitives::{
        ActionDigest, Anchor, Epoch, Output, Spend, Tachygram,
        multiset::{self, Multiset},
    },
    value,
};

/// PCD header type for Tachyon stamps.
pub(crate) struct StampHeader;

impl Header for StampHeader {
    type Data<'source> = (
        multiset::Commitment<ActionDigest>,
        multiset::Commitment<Tachygram>,
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(
        data: &(
            multiset::Commitment<ActionDigest>,
            multiset::Commitment<Tachygram>,
            Anchor,
        ),
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        let action_bytes: [u8; 32] = EqAffine::from(data.0).to_bytes();
        let tachygram_bytes: [u8; 32] = EqAffine::from(data.1).to_bytes();
        out.extend_from_slice(&action_bytes);
        out.extend_from_slice(&tachygram_bytes);
        let anchor_bytes: [u8; 32] = Fp::from(data.2).to_repr();
        out.extend_from_slice(&anchor_bytes);
        out
    }
}

/// Witness data for a single action proof.
pub(crate) struct ActionWitness<'action> {
    /// The authorized action (cv, rk, sig).
    pub(crate) action: &'action Action,
    /// Action randomizer $\alpha$.
    pub(crate) alpha: ActionRandomizer<Witness>,
    /// The note being spent or created.
    pub(crate) note: Note,
    /// Value commitment trapdoor.
    pub(crate) rcv: value::CommitmentTrapdoor,
    /// Accumulator state reference.
    pub(crate) anchor: Anchor,
    /// Epoch index for nullifier derivation.
    pub(crate) epoch: Epoch,
    /// Wallet-wide proof authorizing key.
    pub(crate) pak: &'action ProofAuthorizingKey,
}

/// Leaf step: produces a proof for a single action.
pub(crate) struct ActionStep;

impl Step for ActionStep {
    type Aux<'source> = (Tachygram, Multiset<ActionDigest>, Multiset<Tachygram>);
    type Left = ();
    type Output = StampHeader;
    type Right = ();
    type Witness<'source> = ActionWitness<'source>;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let note_value: i64 = witness.note.value.into();

        // output: rk == [alpha]G
        let is_output = witness.action.rk
            == ActionSigningKey::new(&ActionRandomizer::<Output>(witness.alpha.0, PhantomData))
                .derive_action_public();

        // spend: rk == ak + [alpha]G
        let is_spend = witness.action.rk
            == witness
                .pak
                .ak()
                .derive_action_public(&ActionRandomizer::<Spend>(witness.alpha.0, PhantomData));

        let (tachygram, check_cv): (Tachygram, value::Commitment) = match (is_spend, is_output) {
            | (true, false) => {
                Ok((
                    witness
                        .note
                        .nullifier(witness.pak.nk(), witness.epoch)
                        .into(),
                    witness.rcv.commit(note_value),
                ))
            },
            | (false, true) => {
                // constrain cv: output commits negative value
                Ok((
                    witness.note.commitment().into(),
                    witness.rcv.commit(note_value.neg()),
                ))
            },
            | (true, true) | (false, false) => Err(mock_ragu::Error),
        }?;

        // constrain cv
        if witness.action.cv != check_cv {
            return Err(mock_ragu::Error);
        }

        let action_acc = ActionDigest::try_from(witness.action)
            .map(Multiset::<ActionDigest>::from)
            .map_err(|_err| mock_ragu::Error)?;

        let tachygram_acc = Multiset::<Tachygram>::from(tachygram);

        Ok((
            (action_acc.commit(), tachygram_acc.commit(), witness.anchor),
            (tachygram, action_acc, tachygram_acc),
        ))
    }
}

/// Accumulators from both sides, needed for merge.
#[expect(
    clippy::struct_field_names,
    reason = "left/right prefix is semantically necessary"
)]
pub(crate) struct MergeWitness {
    pub(crate) left_action_acc: Multiset<ActionDigest>,
    pub(crate) left_tachygram_acc: Multiset<Tachygram>,
    pub(crate) right_action_acc: Multiset<ActionDigest>,
    pub(crate) right_tachygram_acc: Multiset<Tachygram>,
}

/// Merge step: combines two stamp proofs.
pub(crate) struct MergeStep;

impl Step for MergeStep {
    type Aux<'source> = (Multiset<ActionDigest>, Multiset<Tachygram>);
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = StampHeader;
    type Witness<'source> = MergeWitness;

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let action_acc = witness.left_action_acc * witness.right_action_acc;
        let tachygram_acc = witness.left_tachygram_acc * witness.right_tachygram_acc;

        let action_commitment = action_acc.commit();
        let tachygram_commitment = tachygram_acc.commit();
        let anchor = left.2.max(right.2);

        let header = (action_commitment, tachygram_commitment, anchor);
        Ok((header, (action_acc, tachygram_acc)))
    }
}
