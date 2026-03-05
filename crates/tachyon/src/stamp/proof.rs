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
use core::cmp;

use ff::PrimeField as _;
use mock_ragu::{self, Application, ApplicationBuilder, Header, Index, Step, Suffix, accumulator};
pub use mock_ragu::{Proof, ValidationError};
use pasta_curves::Fp;

use crate::{
    action::{Action, Effect},
    keys::ProofAuthorizingKey,
    primitives::{Anchor, Epoch, Tachygram},
    witness::ActionPrivate,
};

/// BLAKE2b personalization for action accumulator.
pub(crate) const ACTION_ACC_DOMAIN: &[u8; 16] = b"Tachyon_ActnAccm";
/// BLAKE2b personalization for tachygram accumulator.
pub(crate) const TACHYGRAM_ACC_DOMAIN: &[u8; 16] = b"Tachyon_TgrmAccm";

// ---------------------------------------------------------------------------
// PCD header
// ---------------------------------------------------------------------------

/// PCD header data for a Tachyon stamp.
///
/// Contains the two accumulators and the anchor, carried by the Ragu proof.
/// Not serialized on the wire — the verifier reconstructs it from public data.
#[derive(Clone, Debug)]
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "crate-internal PCD data"
)]
pub(crate) struct StampDigest {
    /// XOR-fold of action digests $H(\mathsf{cv}_i, \mathsf{rk}_i)$.
    pub(crate) action_acc: [u8; 32],
    /// XOR-fold of tachygram hashes.
    pub(crate) tachygram_acc: [u8; 32],
    /// Anchor as Fp repr.
    pub(crate) anchor: [u8; 32],
}

/// PCD header type for Tachyon stamps.
pub(crate) struct StampHeader;

impl Header for StampHeader {
    type Data<'source> = StampDigest;

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &StampDigest) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&data.action_acc);
        out.extend_from_slice(&data.tachygram_acc);
        out.extend_from_slice(&data.anchor);
        out
    }
}

// ---------------------------------------------------------------------------
// Action step (leaf / seed)
// ---------------------------------------------------------------------------

/// Witness data for a single action proof.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "crate-internal witness struct"
)]
pub(crate) struct ActionWitness<'action> {
    /// The authorized action (cv, rk, sig).
    pub(crate) action: &'action Action,
    /// Private witness (note, alpha, rcv).
    pub(crate) witness: &'action ActionPrivate,
    /// Whether this is a spend or output.
    pub(crate) effect: Effect,
    /// Accumulator state reference.
    pub(crate) anchor: Anchor,
    /// Wallet-wide proof authorizing key.
    pub(crate) pak: &'action ProofAuthorizingKey,
}

/// Leaf step: produces a proof for a single action.
pub(crate) struct ActionStep;

impl Step for ActionStep {
    type Aux<'source> = (Vec<Tachygram>, StampDigest);
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
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>), ValidationError>
    {
        // Derive tachygram based on effect
        let tachygram: Tachygram = match witness.effect {
            | Effect::Spend => {
                todo!("derive epoch from anchor");
                let epoch = Epoch::from(0u32);
                let nf = witness.witness.note.nullifier(witness.pak.nk(), epoch);
                nf.into()
            },
            | Effect::Output => {
                let cm = witness.witness.note.commitment();
                cm.into()
            },
        };

        // Compute action accumulator (XOR-fold of H(cv, rk))
        let cv_bytes: [u8; 32] = witness.action.cv.into();
        let rk_bytes: [u8; 32] = witness.action.rk.into();
        let action_acc = accumulator::accumulate_pairs(ACTION_ACC_DOMAIN, &[(cv_bytes, rk_bytes)]);

        // Compute tachygram accumulator (XOR-fold of H(tachygram))
        let tg_fp: Fp = tachygram.into();
        let tg_bytes: [u8; 32] = tg_fp.to_repr();
        let tachygram_acc = accumulator::accumulate(TACHYGRAM_ACC_DOMAIN, &[tg_bytes]);

        // Anchor bytes
        let anchor_fp: Fp = witness.anchor.into();
        let anchor_bytes: [u8; 32] = anchor_fp.to_repr();

        let digest = StampDigest {
            action_acc,
            tachygram_acc,
            anchor: anchor_bytes,
        };

        let aux_digest = digest.clone();
        Ok((digest, (alloc::vec![tachygram], aux_digest)))
    }
}

// ---------------------------------------------------------------------------
// Merge step (fuse)
// ---------------------------------------------------------------------------

/// Merge step: combines two stamp proofs.
pub(crate) struct MergeStep;

impl Step for MergeStep {
    type Aux<'source> = StampDigest;
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = StampHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>), ValidationError>
    {
        let digest = StampDigest {
            action_acc: accumulator::combine(&left.action_acc, &right.action_acc),
            tachygram_acc: accumulator::combine(&left.tachygram_acc, &right.tachygram_acc),
            anchor: cmp::max(left.anchor, right.anchor),
        };
        let aux_digest = digest.clone();
        Ok((digest, aux_digest))
    }
}

// ---------------------------------------------------------------------------
// Application helper
// ---------------------------------------------------------------------------

/// Build a mock Ragu application with the Tachyon steps registered.
#[expect(clippy::expect_used, reason = "mock registration is infallible")]
pub(crate) fn mock_app() -> Application {
    ApplicationBuilder::new()
        .register(ActionStep)
        .expect("register ActionStep")
        .register(MergeStep)
        .expect("register MergeStep")
        .finalize()
        .expect("finalize")
}
