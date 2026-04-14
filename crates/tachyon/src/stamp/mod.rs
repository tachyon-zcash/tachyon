//! Stamps and anchors.
//!
//! A stamp carries the tachygram list, the epoch anchor, and the proof:
//!
//! - **Tachygrams**: Listed individually
//! - **Anchor**: Accumulator state reference (epoch)
//! - **Proof**: The Ragu PCD proof (rerandomized)
//!
//! The PCD header data `(action_commitment, tachygram_commitment, anchor)`
//! is **not serialized** on the stamp — the verifier reconstructs polynomial
//! commitments from public data and passes them as the header to Ragu
//! `verify()`.

#![allow(clippy::type_complexity, reason = "todo")]

extern crate alloc;

pub mod proof;

use alloc::vec::Vec;
use core::{error::Error, fmt};

use core2::io::{self, Read, Write};
use lazy_static::lazy_static;
use mock_ragu::{Application, ApplicationBuilder, proof::PROOF_SIZE_COMPRESSED};
pub use proof::Proof;
use rand_core::CryptoRng;

use self::proof::{ActionStep, MergeStep, MergeWitness, StampHeader};
use crate::{
    ActionDigest, Epoch,
    entropy::{ActionRandomizer, Witness},
    keys::{ProofAuthorizingKey, public},
    note::Note,
    primitives::{ActionDigestError, Anchor, Tachygram, multiset::Multiset},
    value,
};

/// Marker for a bundle that has not yet been proven.
///
/// This is the initial state for a newly constructed bundle.
/// Proving produces a [`Stamp`]; stripping produces an [`Adjunct`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unproven;

/// Marker for a stripped bundle that depends on an aggregate stamp.
///
/// Carries an optional index referencing the stamped bundle on the surrounding
/// block that covers this bundle's tachygrams.  Assigned by the miner during
/// block assembly; defaults to `None`.
///
/// Serialization will fail if the index has not been assigned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Adjunct(Option<u8>);

impl Adjunct {
    /// Create a new `Adjunct` with the given `stamp_index`.
    ///
    /// # Panics
    ///
    /// Panics if the index is greater than 0xFC.
    #[must_use]
    pub fn new(stamp_index: u8) -> Self {
        assert!(stamp_index <= 0xFC, "stamp index must be <= 0xFC");
        Self(Some(stamp_index))
    }

    /// Set `stamp_index` to associate a stripped adjunct with an aggregate
    /// stamp in the same block.
    ///
    /// # Panics
    ///
    /// Panics if the index is greater than 0xFC.
    pub fn set_index(&mut self, set_index: u8) {
        assert!(set_index <= 0xFC, "stamp index must be <= 0xFC");
        self.0 = Some(set_index);
    }

    /// Get the `stamp_index` associated with this stripped adjunct.
    ///
    /// Returns `None` if the `stamp_index` has not been assigned.
    #[must_use]
    pub const fn get_index(&self) -> Option<u8> {
        self.0
    }
}

/// Error during stamp verification.
#[derive(Clone, Debug)]
pub enum VerificationError {
    /// An action's cv or rk is the identity point.
    ActionDigest(ActionDigestError),
    /// The proof system returned an error.
    ProofSystem,
    /// The proof did not verify against the reconstructed header.
    Disproved,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | &Self::ActionDigest(err) => write!(f, "action digest error: {err}"),
            | &Self::ProofSystem => write!(f, "proof system error"),
            | &Self::Disproved => write!(f, "proof did not verify"),
        }
    }
}

impl Error for VerificationError {}

/// Everything needed to produce a [`Stamp`].
///
/// Each action is described by a public descriptor `(cv, rk)` and a
/// private witness `(alpha, note, rcv)`. The `prove` method generates
/// a leaf proof for each action, then merges pairwise into a single
/// stamp.
///
/// Construct via [`Plan::new`] with pre-derived action witnesses, or
/// via [`bundle::Plan::stamp_plan`](crate::bundle::Plan::stamp_plan)
/// for the typed single-party path.
#[derive(Clone, Debug)]
pub struct Plan {
    actions: Vec<(
        (value::Commitment, public::ActionVerificationKey),
        (ActionRandomizer<Witness>, Note, value::CommitmentTrapdoor),
    )>,
    anchor: Anchor,
    epoch: Epoch,
}

impl Plan {
    /// Create a stamp plan from paired action descriptors and witnesses.
    ///
    /// The caller is responsible for deriving alpha from theta (or
    /// obtaining it through other means).
    #[must_use]
    pub const fn new(
        actions: Vec<(
            (value::Commitment, public::ActionVerificationKey),
            (ActionRandomizer<Witness>, Note, value::CommitmentTrapdoor),
        )>,
        anchor: Anchor,
        epoch: Epoch,
    ) -> Self {
        Self {
            actions,
            anchor,
            epoch,
        }
    }

    /// Execute the proof, producing a [`Stamp`].
    ///
    /// Proves each action as a leaf, then merges pairwise into a single
    /// stamp covering all actions.
    pub fn prove<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        pak: &ProofAuthorizingKey,
    ) -> Result<Stamp, ProveError> {
        let mut stamps_and_accs: Vec<(Stamp, Multiset<ActionDigest>)> = Vec::new();

        for (descriptor, witness) in self.actions {
            let (stamp, (action_acc, _tg_acc)) =
                Stamp::prove_action(rng, descriptor, witness, self.anchor, self.epoch, pak)
                    .map_err(|_err| ProveError::ProofFailed(stamps_and_accs.len()))?;

            stamps_and_accs.push((stamp, action_acc));
        }

        // TODO: support zero actions
        if stamps_and_accs.is_empty() {
            return Err(ProveError::NoActions);
        }

        while stamps_and_accs.len() > 1 {
            let (right_stamp, right_acc) = stamps_and_accs.pop().ok_or(ProveError::NoActions)?;
            let (left_stamp, left_acc) = stamps_and_accs.pop().ok_or(ProveError::NoActions)?;
            let (merged, (merged_acc, _tg_acc)) =
                Stamp::prove_merge(rng, left_stamp, left_acc, right_stamp, right_acc)
                    .map_err(|_err| ProveError::MergeFailed)?;
            stamps_and_accs.push((merged, merged_acc));
        }

        let (stamp, _acc) = stamps_and_accs.pop().ok_or(ProveError::NoActions)?;
        Ok(stamp)
    }
}

/// Errors that can occur while proving a stamp.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProveError {
    /// The plan has no actions to prove.
    NoActions,
    /// Proof creation failed for the action at this index.
    ProofFailed(usize),
    /// Stamp merge failed.
    MergeFailed,
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::NoActions => write!(f, "no actions to prove"),
            | Self::ProofFailed(idx) => write!(f, "proof failed at action {idx}"),
            | Self::MergeFailed => write!(f, "stamp merge failed"),
        }
    }
}

impl Error for ProveError {}

/// A stamp carrying tachygrams, anchor, and proof.
///
/// Present in [`Stamped`](crate::Stamped) bundles.
/// Stripped during aggregation and merged into the aggregate's stamp.
///
/// The PCD header `(action_acc, tachygram_acc, anchor)` is not stored
/// here — the verifier reconstructs it from public data and passes it as
/// the header to Ragu `verify()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// Tachygrams (nullifiers and note commitments) for data availability.
    ///
    /// The number of tachygrams can be greater than the number of actions.
    pub tachygrams: Vec<Tachygram>,

    /// Reference to tachyon accumulator state (epoch).
    pub anchor: Anchor,

    /// The Ragu proof bytes.
    pub proof: Proof,
}

impl Stamp {
    /// Creates a leaf stamp for a single action (ACTION STEP).
    ///
    /// The circuit infers spend vs output by testing `rk` against `[alpha]G`.
    /// The proof is rerandomized before returning.
    ///
    /// Leaf stamps are combined via [`prove_merge`](Self::prove_merge).
    #[expect(clippy::type_complexity, reason = "PCD accumulators")]
    pub fn prove_action<RNG: CryptoRng>(
        rng: &mut RNG,
        (cv, rk): (value::Commitment, public::ActionVerificationKey),
        (alpha, note, rcv): (ActionRandomizer<Witness>, Note, value::CommitmentTrapdoor),
        anchor: Anchor,
        epoch: Epoch,
        pak: &ProofAuthorizingKey,
    ) -> Result<(Self, (Multiset<ActionDigest>, Multiset<Tachygram>)), mock_ragu::Error> {
        let app = &PROOF_SYSTEM;
        let (proof, (tachygram, action_acc, tachygram_acc)) = app.seed(
            rng,
            &ActionStep,
            proof::ActionWitness {
                descriptor: (cv, rk),
                secrets: (alpha, note, rcv),
                anchor,
                epoch,
                pak,
            },
        )?;

        let pcd = proof.carry::<StampHeader>((action_acc.commit(), tachygram_acc.commit(), anchor));

        let rerand = app.rerandomize(pcd, rng)?;

        Ok((
            Self {
                tachygrams: alloc::vec![tachygram],
                anchor,
                proof: rerand.proof,
            },
            (action_acc, tachygram_acc),
        ))
    }

    /// Merges this stamp with another, combining tachygrams and proofs.
    ///
    /// Assuming the anchor is an append-only accumulator, a later anchor should
    /// be a superset of an earlier anchor.
    ///
    /// The accumulators (`action_acc`, `tachygram_acc`) are merged inside the
    /// circuit via polynomial multiplication. [`MergeStep`] multiplies the
    /// polynomials, recommits, and takes the max anchor.
    #[expect(clippy::type_complexity, reason = "deal with it")]
    pub fn prove_merge<RNG: CryptoRng>(
        rng: &mut RNG,
        left: Self,
        left_actions: Multiset<ActionDigest>,
        right: Self,
        right_actions: Multiset<ActionDigest>,
    ) -> Result<(Self, (Multiset<ActionDigest>, Multiset<Tachygram>)), mock_ragu::Error> {
        let app = &PROOF_SYSTEM;

        let left_tachygrams = Multiset::<Tachygram>::from(left.tachygrams.as_slice());
        let right_tachygrams = Multiset::<Tachygram>::from(right.tachygrams.as_slice());

        let left_pcd = left.proof.carry::<StampHeader>((
            left_actions.commit(),
            left_tachygrams.commit(),
            left.anchor,
        ));

        let right_pcd = right.proof.carry::<StampHeader>((
            right_actions.commit(),
            right_tachygrams.commit(),
            right.anchor,
        ));

        let merge_witness = MergeWitness {
            left_action_acc: left_actions,
            left_tachygram_acc: left_tachygrams,
            right_action_acc: right_actions,
            right_tachygram_acc: right_tachygrams,
        };

        let (proof, (merged_action_acc, merged_tachygram_acc)) =
            app.fuse(rng, &MergeStep, merge_witness, left_pcd, right_pcd)?;

        let merged_anchor = left.anchor.max(right.anchor);
        let merged_tachygrams = [left.tachygrams, right.tachygrams].concat();

        let merged_header = (
            merged_action_acc.commit(),
            merged_tachygram_acc.commit(),
            merged_anchor,
        );
        let carried = proof.carry::<StampHeader>(merged_header);
        let rerand = app.rerandomize(carried, rng)?;

        Ok((
            Self {
                tachygrams: merged_tachygrams,
                anchor: merged_anchor,
                proof: rerand.proof,
            },
            (merged_action_acc, merged_tachygram_acc),
        ))
    }

    /// Verifies this stamp's proof by reconstructing the PCD header from public
    /// data.
    ///
    /// The verifier recomputes the action and tachygram polynomial commitments
    /// from the public actions and tachygrams, constructs the PCD header,
    /// and calls Ragu `verify(Pcd { proof, data: header })`. The proof
    /// only verifies against the header that matches the circuit's honest
    /// execution — a mismatched header causes verification failure.
    pub fn verify(
        &self,
        actions: &Multiset<ActionDigest>,
        rng: &mut impl CryptoRng,
    ) -> Result<(), VerificationError> {
        let app = &PROOF_SYSTEM;

        let action_commitment = actions.commit();

        let tachygram_commitment = <Multiset<Tachygram>>::from(self.tachygrams.as_slice()).commit();

        let pcd = self.proof.clone().carry::<StampHeader>((
            action_commitment,
            tachygram_commitment,
            self.anchor,
        ));

        let valid = app
            .verify(&pcd, rng)
            .map_err(|_err| VerificationError::ProofSystem)?;

        if valid {
            Ok(())
        } else {
            Err(VerificationError::Disproved)
        }
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        action, effect,
        entropy::ActionEntropy,
        keys::private,
        note::{self, Note},
        value,
    };

    fn make_spend(
        rng: &mut StdRng,
        sk: &private::SpendingKey,
        value_amount: u64,
    ) -> action::Plan<effect::Spend> {
        let pak = sk.derive_proof_private();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(value_amount),
            psi: note::NullifierTrapdoor::from(Fp::ZERO),
            rcm: note::CommitmentTrapdoor::from(Fp::ZERO),
        };
        let rcv = value::CommitmentTrapdoor::random(rng);
        let theta = ActionEntropy::random(rng);
        let derive_rk = { move |alpha| pak.ak().derive_action_public(&alpha) };
        action::Plan::spend(note, theta, rcv, derive_rk)
    }

    fn make_output(
        rng: &mut StdRng,
        sk: &private::SpendingKey,
        value_amount: u64,
    ) -> action::Plan<effect::Output> {
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(value_amount),
            psi: note::NullifierTrapdoor::from(Fp::ZERO),
            rcm: note::CommitmentTrapdoor::from(Fp::ZERO),
        };
        let rcv = value::CommitmentTrapdoor::random(rng);
        let theta = ActionEntropy::random(rng);
        action::Plan::output(note, theta, rcv)
    }

    fn prove_spend(
        rng: &mut StdRng,
        plan: &action::Plan<effect::Spend>,
        anchor: Anchor,
        epoch: Epoch,
        pak: &ProofAuthorizingKey,
    ) -> (Stamp, Multiset<ActionDigest>) {
        let alpha = plan
            .theta
            .randomizer::<effect::Spend>(&plan.note.commitment());
        let (stamp, (acc, _)) = Stamp::prove_action(
            rng,
            (plan.cv(), plan.rk),
            (alpha.into(), plan.note, plan.rcv),
            anchor,
            epoch,
            pak,
        )
        .expect("prove_action");
        (stamp, acc)
    }

    fn prove_output(
        rng: &mut StdRng,
        plan: &action::Plan<effect::Output>,
        anchor: Anchor,
        epoch: Epoch,
        pak: &ProofAuthorizingKey,
    ) -> (Stamp, Multiset<ActionDigest>) {
        let alpha = plan
            .theta
            .randomizer::<effect::Output>(&plan.note.commitment());
        let (stamp, (acc, _)) = Stamp::prove_action(
            rng,
            (plan.cv(), plan.rk),
            (alpha.into(), plan.note, plan.rcv),
            anchor,
            epoch,
            pak,
        )
        .expect("prove_action");
        (stamp, acc)
    }

    #[test]
    fn prove_action_then_verify() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let plan = make_spend(&mut rng, &sk, 500);
        let (stamp, _acc) = prove_spend(&mut rng, &plan, anchor, epoch, &pak);

        stamp
            .verify(
                &Multiset::from(ActionDigest::new(plan.cv(), plan.rk).expect("valid")),
                &mut rng,
            )
            .expect("verify should succeed");
    }

    #[test]
    fn verify_rejects_wrong_action() {
        let mut rng = StdRng::seed_from_u64(1);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let spend = make_spend(&mut rng, &sk, 500);
        let (stamp, _acc) = prove_spend(&mut rng, &spend, anchor, epoch, &pak);

        let output = make_output(&mut rng, &sk, 200);

        assert!(
            stamp
                .verify(
                    &Multiset::from(ActionDigest::new(output.cv(), output.rk).expect("valid")),
                    &mut rng,
                )
                .is_err(),
            "verify with wrong action must fail"
        );
    }

    #[test]
    fn prove_merge_then_verify() {
        let mut rng = StdRng::seed_from_u64(2);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let spend = make_spend(&mut rng, &sk, 500);
        let (stamp_a, acc_a) = prove_spend(&mut rng, &spend, anchor, epoch, &pak);

        let output = make_output(&mut rng, &sk, 200);
        let (stamp_b, acc_b) = prove_output(&mut rng, &output, anchor, epoch, &pak);

        let (merged, (merged_acc, _)) =
            Stamp::prove_merge(&mut rng, stamp_a, acc_a, stamp_b, acc_b).expect("prove_merge");

        merged
            .verify(&merged_acc, &mut rng)
            .expect("merged stamp should verify");
    }

    #[test]
    fn merged_stamp_rejects_partial_actions() {
        let mut rng = StdRng::seed_from_u64(3);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let spend = make_spend(&mut rng, &sk, 500);
        let (stamp_a, acc_a) = prove_spend(&mut rng, &spend, anchor, epoch, &pak);

        let output = make_output(&mut rng, &sk, 200);
        let (stamp_b, acc_b) = prove_output(&mut rng, &output, anchor, epoch, &pak);

        let (merged, _) =
            Stamp::prove_merge(&mut rng, stamp_a, acc_a, stamp_b, acc_b).expect("prove_merge");

        assert!(
            merged
                .verify(
                    &Multiset::from(ActionDigest::new(spend.cv(), spend.rk).expect("valid")),
                    &mut rng,
                )
                .is_err(),
            "verify with partial actions must fail"
        );
    }
}

/// The serialized size of a proof, for the `stampTachyon` compactsize.
pub(crate) const fn proof_serialized_size() -> usize {
    PROOF_SIZE_COMPRESSED
}

/// Read a proof of the given byte length.
pub(crate) fn read_proof_sized<R: Read>(mut reader: R, size: usize) -> io::Result<Proof> {
    use alloc::boxed::Box;

    if size != PROOF_SIZE_COMPRESSED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected proof size",
        ));
    }

    let mut bytes = alloc::vec![0u8; size];
    reader.read_exact(&mut bytes)?;
    let arr: Box<[u8; PROOF_SIZE_COMPRESSED]> = bytes
        .into_boxed_slice()
        .try_into()
        .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "proof buffer wrong size"))?;
    Proof::try_from(arr.as_ref())
        .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "invalid proof encoding"))
}

/// Write a proof's raw bytes (without length prefix).
pub(crate) fn write_proof<W: Write>(mut writer: W, proof: &Proof) -> io::Result<()> {
    let bytes = proof.serialize();
    writer.write_all(bytes.as_ref())
}

lazy_static! {
    static ref PROOF_SYSTEM: Application = {
        #[expect(clippy::expect_used, reason = "mock registration is infallible")]
        ApplicationBuilder::new()
            .register(ActionStep)
            .expect("register ActionStep")
            .register(MergeStep)
            .expect("register MergeStep")
            .finalize()
            .expect("finalize")
    };
}
