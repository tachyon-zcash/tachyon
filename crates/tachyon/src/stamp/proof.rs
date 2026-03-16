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
//! The prover supplies private inputs (note, value commitment trapdoor) per
//! action that the circuit checks against the public action and tachygram.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
pub use mock_ragu::Proof;
use mock_ragu::{self, Header, Index, Step, Suffix};
use pasta_curves::{EqAffine, Fp, group::GroupEncoding as _};

use pasta_curves::Fq;

use crate::{
    action::{self, Action},
    entropy::Randomizer,
    keys::{ProofAuthorizingKey, private},
    note::Note,
    primitives::{
        ActionDigest, Anchor, Epoch, Tachygram,
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
    /// Action randomizer $\alpha$ for rk derivation (raw scalar).
    pub(crate) alpha: Fq,
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
        // Determine effect from the sign of the value commitment.
        // Exactly one must match (XOR).
        let value: i64 = witness.note.value.into();
        let is_spend = witness.rcv.commit(value) == witness.action.cv;
        let is_output = witness.rcv.commit(-value) == witness.action.cv;
        assert!(
            is_spend ^ is_output,
            "cv must match exactly one of spend or output commitment"
        );

        // Verify rk derivation from alpha.
        let expected_rk = if is_spend {
            // rk = ak + [alpha]G
            let alpha = Randomizer::<action::Spend>(witness.alpha, core::marker::PhantomData);
            witness.pak.ak().derive_action_public(&alpha)
        } else {
            // rk = [alpha]G
            let alpha = Randomizer::<action::Output>(witness.alpha, core::marker::PhantomData);
            private::ActionSigningKey::new(&alpha).derive_action_public()
        };
        assert!(
            witness.action.rk == expected_rk,
            "rk must match derivation from alpha"
        );

        let tachygram: Tachygram = if is_spend {
            let nf = witness
                .note
                .nullifier(witness.pak.nk(), witness.epoch);
            nf.into()
        } else {
            let cm = witness.note.commitment();
            cm.into()
        };

        let action_acc = ActionDigest::try_from(witness.action)
            .map(Multiset::<ActionDigest>::from)
            .map_err(|_err| mock_ragu::Error)?;
        let action_commitment = action_acc.commit();

        let tachygram_acc = Multiset::<Tachygram>::from(tachygram);
        let tachygram_commitment = tachygram_acc.commit();

        let header = (action_commitment, tachygram_commitment, witness.anchor);
        Ok((header, (tachygram, action_acc, tachygram_acc)))
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
