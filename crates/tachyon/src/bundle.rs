//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by bundle state `S: BundleState`.
//! Action descriptors and signatures are constant through state transitions;
//! only the stamp changes.
//!
//! - `Bundle<ProofStamp<P>>`: bundle with a proof stamp, listing the txids of
//!   the other transactions whose bundles it covers
//! - `Bundle<StrippedStamp>`: proof stamp removed, covered by an aggregate that
//!   lists this bundle's txid
//! - [`TachyonBundle`]: enum of the on-wire forms for block items
//!
//! # Consensus wire format
//!
//! The first byte `tachyonBundleState` selects one of three bundle states:
//!
//! | value         | state         | bundle contents                       |
//! | ------------- | ------------- | ------------------------------------- |
//! | `0b0000_0000` | non-tachyon   | no bundle                             |
//! | `0b0000_0001` | proof stamp   | bundle with anchor, tachygrams, proof |
//! | `0b0000_0010` | stripped      | bundle with tachygrams and no proof   |
//! | `...`         | *reserved*    | *n/a*                                 |
//!
//! Any other byte is invalid. Stripped innocents and adjuncts share the same
//! wire layout (both write `0x02` + body + the stripped trailer).
//!
//! ## No Bundle
//!
//! When `tachyonBundleState` is 0x00, there is no bundle.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `tachyonBundleState`  | u8                   | `0x00`                                   |
//!
//! ## Tachyon Bundle
//!
//! When `tachyonBundleState` is not 0x00, there is a tachyon bundle.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `tachyonBundleState`  | u8                   | `0x01` or `0x02`                         |
//! | `valueBalanceTachyon` | i64                  | net value of tachyon actions and max fee |
//! | `nActionsTachyon`     | compactsize          | number of tachyon actions                |
//! | `vActionsTachyon`     | 64 * nActionsTachyon | (cv: 32 bytes, rk: 32 bytes)             |
//! | `cvFeeMaxTachyon`     | 32 bytes             | max fee note value commitment            |
//! | `vActionSigsTachyon`  | 64 * nActionsTachyon | authorization per action over tx sighash |
//! | `bindingSigTachyon`   | 64 bytes             | binding over tx sighash                  |
//! | `nMemoTachyon`        | compactsize          | memo length, `0` when absent             |
//! | `vMemoTachyon`        | nMemoTachyon bytes   | opaque recipient-directed payload        |
//!
//! `cvFeeMaxTachyon` is a canonical non-identity point. The bundle
//! contributes `valueBalanceTachyon + vFeeTachyon` to the transaction balance.
//! `nActionsTachyon` is at most 4095, the most actions whose tachygrams fit
//! one set polynomial beside the bundle's fee change.
//!
//! The memo is effecting data, so it is covered by the transaction sighash
//! rather than by `auth_digest`. Its length is public, and `nMemoTachyon == 0`
//! reveals that no payload is present; the payload is variable-length because
//! it carries key-exchange ciphertexts on first contact and ordinary memo text
//! otherwise, sizes that differ by more than an order of magnitude.
//!
//! ### Proof stamp
//!
//! When `tachyonBundleState == 1`, the bundle carries a proof stamp.
//!
//! | Name               | Format                    | Description                               |
//! | ------------------ | ------------------------- | ----------------------------------------- |
//! | `vTachygrams`      | 64 * nActionsTachyon + 32 | each action's pair, then the fee change   |
//! | `vFeeTachyon`      | LE64                      | fee, at most `MAX_MONEY`                  |
//! | `anchorTachyon`    | 32 bytes                  | pool state reference                      |
//! | `cTachygrams`      | 32 bytes                  | commitment to the covered tachygram union |
//! | `nAdjunctsTachyon` | compactSize               | number of adjuncts, `0` for an autonome   |
//! | `vAdjunctsTachyon` | 32 * nAdjunctsTachyon     | txids of the other covered transactions   |
//! | `sizeProofTachyon` | compactSize               | length of `proofTachyon` in bytes         |
//! | `proofTachyon`     | `byte[sizeProofTachyon]`  | the Ragu stamp proof                      |
//!
//! The prover writes each pair smaller tachygram first, so the order reveals
//! neither member's role. The encoding does not require it.
//!
//! `cTachygrams` is carried rather than derived, so full validation must
//! confirm it against every covered bundle's `vTachygrams`. Anchor
//! advancement then reads the point instead of rebuilding it.
//!
//! `vAdjunctsTachyon` is strictly ascending by bytewise comparison, so it holds
//! no repeat. Every adjunct holds at least its fee change, so a stamp with
//! `2 * nActionsTachyon + nAdjunctsTachyon + 2 > 2^13` never verifies and is
//! rejected at read.
//!
//! Consensus carries [`Compressed`](stamp::Compressed) proofs, and
//! `Bundle<ProofStamp<Uncompressed>>` uses the same `0x01` layout with the
//! uncompressed length while stamps are merged and lifted outside consensus.
//!
//! ## Stripped stamp
//!
//! When `tachyonBundleState == 2`, the bundle carries a stripped trailer.
//!
//! | Name          | Format                    | Description                             |
//! | ------------- | ------------------------- | --------------------------------------- |
//! | `vTachygrams` | 64 * nActionsTachyon + 32 | each action's pair, then the fee change |
//! | `vFeeTachyon` | LE64                      | fee, at most `MAX_MONEY`                |
//!
//! The transaction `auth_digest` contribution commits either stamp as
//! `hStampTachyon`, over `vTachygrams`, the fee and `hStampProofTachyon`. For a
//! proof stamp, `hStampProofTachyon` covers the stamp proof, its header and the
//! adjunct list; for a stripped stamp, it is
//! [`blake2b::STAMP_PROOF_STRIPPED`]. See [`blake2b::stamp_digest`].

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{cmp::Ordering, iter, ops::Neg as _};

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, From, IsVariant, PartialEq, TryInto};
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use ragu_core::pasta::Pasta;
use rand_core::CryptoRng;
use udon::curve::Affine as _;

use crate::{
    ActionDigest, ActionDigestError, Note, Tachygram, TachygramSetCommit, TachygramSetPoly,
    action::{self, Action},
    digest::blake2b,
    fee,
    keys::{private, public},
    primitives::{Anchor, effect},
    reddsa, serialization,
    stamp::{
        self, ProofStamp, ProveError, StampState, StrippedStamp, Unproven,
        proof::{App, pool},
    },
    value,
};

/// The `tachyonBundleState` wire byte. See the module-level wire format
/// documentation for its role.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
#[repr(u8)]
pub enum StateByte {
    /// No bundle.
    NoBundle = 0b0000_0000u8,
    /// Proof stamped bundle.
    ProofStamped = 0b0000_0001u8,
    /// Stripped bundle.
    Stripped = 0b0000_0010u8,
}

impl From<StateByte> for u8 {
    #[expect(clippy::as_conversions, reason = "repr u8")]
    fn from(val: StateByte) -> Self {
        val as Self
    }
}

impl StateByte {
    pub(super) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        match u8::from_le_bytes(byte) {
            0b0000_0000u8 => Ok(Self::NoBundle),
            0b0000_0001u8 => Ok(Self::ProofStamped),
            0b0000_0010u8 => Ok(Self::Stripped),
            _other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid bundle state",
            )),
        }
    }

    pub(super) fn write<W: Write>(self, mut writer: W) -> io::Result<()> {
        #[expect(clippy::as_conversions, reason = "repr u8")]
        writer.write_all(&(self as u8).to_le_bytes())
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Unproven {}
    impl<P: super::stamp::Proof> Sealed for super::ProofStamp<P> {}
    impl Sealed for super::StrippedStamp {}
}

/// Sealed trait constraining bundle state types.
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
pub trait BundleState: sealed::Sealed {}

impl<T: sealed::Sealed> BundleState for T {}

/// A Tachyon transaction bundle parameterized by bundle state `S`.
#[derive(Clone, Debug)]
pub struct Bundle<S: BundleState + ?Sized> {
    /// Net value of spends minus outputs and max fee.
    pub value_balance: value::Balance,

    /// Each action's descriptor and its signature over the transaction
    /// sighash, in wire order.
    pub action_sigs: Vec<(action::Descriptor, action::Signature)>,

    /// The max fee note's value commitment.
    pub cv_feemax: value::Commitment,

    /// Binding signature over the transaction sighash.
    pub binding_sig: Signature,

    /// Opaque recipient-directed payload, empty when absent.
    pub memo: Vec<u8>,

    /// Bundle state: `Unproven`, `ProofStamp`, or `StrippedStamp`.
    pub stamp: S,
}

impl<S: StampState + 'static> PartialEq for Bundle<S> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment() == other.commitment() && self.auth_digest() == other.auth_digest()
    }
}

impl<S: BundleState + ?Sized> Bundle<S> {
    /// Collect the descriptors of all actions in the bundle, preserving wire
    /// order and duplicates.
    ///
    /// Multiplicity is significant to both the bundle commitment and proof
    /// verification, so callers must not deduplicate these.
    pub fn descriptors(&self) -> impl ExactSizeIterator<Item = action::Descriptor> {
        // Do NOT sort here: maintain order as constructed.
        self.action_sigs.iter().map(|&(desc, _)| desc)
    }

    /// Assemble the bundle's actions: each descriptor and signature with the
    /// tachygram pair the stamp holds at the same position.
    pub fn actions(&self) -> impl ExactSizeIterator<Item = Action>
    where
        S: StampState,
    {
        self.action_sigs
            .iter()
            .zip(&self.stamp.tachygrams().pairs)
            .map(|(&(descriptor, sig), &tg)| Action {
                descriptor,
                tg,
                sig,
            })
    }

    /// Iterates over action descriptors and their certified tachygram pairs.
    pub fn action_tachygrams(
        &self,
    ) -> impl ExactSizeIterator<Item = (action::Descriptor, (Tachygram, Tachygram))>
    where
        S: StampState,
    {
        self.descriptors()
            .zip(self.stamp.tachygrams().pairs.iter().copied())
    }

    /// The bundle's fee descriptor.
    #[must_use]
    pub fn fee_descriptor(&self) -> fee::Descriptor
    where
        S: StampState,
    {
        fee::Descriptor {
            cv_feemax: self.cv_feemax,
            v_fee: self.stamp.fee(),
            fee_change: self.stamp.tachygrams().fee_change,
        }
    }

    /// Digest the bundle's effecting data.
    ///
    /// This contributes to the transaction sighash. The stamp and the fee are
    /// excluded because they are considered authorizing data, and are malleable
    /// during aggregation. The max fee note's value commitment is included,
    /// fixing the maximum fee and the fee change note's owner. The memo is
    /// included, so a miner cannot strip the payload and leave the block
    /// committing to the same transaction.
    ///
    /// The digest binds actions in wire order and is therefore sensitive to
    /// their ordering.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let descriptors: Vec<[u8; 64]> = self.descriptors().collect();
        blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&descriptors),
            self.value_balance.into(),
            &self.cv_feemax.into(),
            &blake2b::memo_digest(&self.memo),
        )
    }

    /// Verify the bundle's binding signature and all action signatures.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError`] if the binding signature does not verify,
    /// or if any action signature does not verify under its own `rk`.
    pub fn verify_signatures(&self, sighash: &[u8; 32]) -> Result<(), SignatureError> {
        // 1. Derive bvk from public data
        let bvk = public::BindingVerificationKey::derive(
            self.descriptors()
                .map(|desc| desc.cv)
                .chain([self.cv_feemax]),
            self.value_balance,
        );

        // 2. Verify binding signature
        bvk.verify(sighash, &self.binding_sig)
            .map_err(|_err| SignatureError::Binding(self.binding_sig))?;

        // 3. Verify each action signature
        for &(desc, sig) in &self.action_sigs {
            desc.rk
                .verify(sighash, &sig)
                .map_err(|_err| SignatureError::Action(sig))?;
        }

        Ok(())
    }
}

/// Errors from bundle signature verification.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// The binding signature is invalid.
    #[display("invalid binding signature {_0:?}")]
    Binding(#[error(not(source))] Signature),
    /// An action signature is invalid.
    #[display("invalid action signature {_0:?}")]
    Action(#[error(not(source))] action::Signature),
}

/// Errors during coverage verification.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum VerifyCoverageError {
    /// The covered tachygrams exceed one set polynomial.
    #[display("covered actions and fees exceed the polynomial rank")]
    TooLarge,
    /// The actions are not unique.
    #[display("actions are not unique")]
    DuplicateActions,
    /// The fees are not unique.
    #[display("fees are not unique")]
    DuplicateFees,
    /// A tachygram repeats in the covered union.
    #[display("tachygrams are not unique")]
    DuplicateTachygrams,
    /// A covered action or fee has no digest.
    #[display("action digest error: {_0}")]
    ActionDigest(ActionDigestError),
    /// The covered tachygrams do not reproduce the stamp's set commitment.
    #[display("tachygrams do not reproduce the set commitment")]
    WrongSet,
}

/// Errors during bundle verification.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum VerificationError {
    /// The bundle signatures did not verify.
    #[display("signature verification error: {_0}")]
    Signatures(SignatureError),
    /// An error occurred while verifying the coverage.
    #[display("coverage verification error: {_0}")]
    Coverage(VerifyCoverageError),
    /// An error occurred while verifying the proof.
    #[display("proof verification error: {_0}")]
    Proof(ragu_core::Error),
    /// The proof did not verify.
    #[display("proof did not verify")]
    Disproved,
}

/// Errors that can occur while signing a bundle plan.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum PlanError {
    /// The signatures do not match the planned actions.
    #[display("planned actions do not match signed actions")]
    ActionSigMismatch,
    /// The value balance overflows the representable range.
    #[display("value balance overflow")]
    BalanceOverflow,
}

/// A complete bundle plan, awaiting authorization.
#[derive(Clone, Debug)]
pub struct Plan {
    /// Spend action plans.
    spends: Vec<action::Plan<effect::Spend>>,

    /// Output action plans.
    outputs: Vec<action::Plan<effect::Output>>,

    /// Max fee note.
    max_fee_note: Note,

    /// Opaque recipient-directed payload, empty when absent.
    memo: Vec<u8>,
}

impl Plan {
    /// Create a new bundle plan from assembled action plans and a max fee note,
    /// carrying no memo.
    #[must_use]
    pub const fn new(
        spends: Vec<action::Plan<effect::Spend>>,
        outputs: Vec<action::Plan<effect::Output>>,
        max_fee_note: Note,
    ) -> Self {
        Self {
            spends,
            outputs,
            max_fee_note,
            memo: Vec::new(),
        }
    }

    /// Attach an opaque recipient-directed payload, replacing any existing one.
    ///
    /// The payload is effecting data, so it must be set before
    /// [`Self::commitment`] is taken for the sighash.
    #[must_use]
    pub fn with_memo(self, memo: Vec<u8>) -> Self {
        Self { memo, ..self }
    }

    /// Iterate over all actions in the plan, mapping with the provided
    /// functions. It is equivalent to calling `transform_spend` for each spend
    /// and `transform_output` for each output.
    pub fn iter_actions<T>(
        &self,
        transform_spend: impl Fn(&action::Plan<effect::Spend>) -> T,
        transform_output: impl Fn(&action::Plan<effect::Output>) -> T,
    ) -> impl Iterator<Item = T> {
        let spend_transform = self.spends.iter().map(transform_spend);
        let output_transform = self.outputs.iter().map(transform_output);
        spend_transform.chain(output_transform)
    }

    /// Collect the descriptors of all actions in the plan, sorted and
    /// deduplicated.
    ///
    /// This is the prover-side set. Contrast [`Bundle::descriptors`], the wire
    /// multiset that preserves order and duplicates.
    #[must_use]
    pub fn descriptors(&self) -> BTreeSet<action::Descriptor> {
        self.iter_actions(action::Plan::descriptor, action::Plan::descriptor)
            .collect()
    }

    /// Derive `value_balance` from note values.
    ///
    /// $$
    ///   (\sum_i v_{\text{spend},i}) -
    ///   (\sum_j v_{\text{output},j}) -
    ///   v_\text{feemax}
    /// $$
    ///
    /// # Errors
    ///
    /// Fails if the final balance falls outside `-MAX_MONEY..=MAX_MONEY`.
    /// Intermediate accumulating states are not constrained.
    pub fn value_balance(&self) -> Result<value::Balance, value::OutOfRange> {
        value::Balance::try_from(
            self.iter_actions(
                |plan| i128::from(plan.note.value),
                |plan| i128::from(plan.note.value).neg(),
            )
            .chain([i128::from(self.max_fee_note.value).neg()])
            .sum::<i128>(),
        )
    }

    /// Compute a digest of all the bundle's effecting data.
    ///
    /// # Errors
    ///
    /// Fails if the value balance overflows the representable range.
    pub fn commitment(&self) -> Result<[u8; 32], value::OutOfRange> {
        let desc_bytes: Vec<[u8; 64]> = self.descriptors().into_iter().collect();

        Ok(blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&desc_bytes),
            self.value_balance()?.into(),
            &self.max_fee_note.cv_feemax().into(),
            &blake2b::memo_digest(&self.memo),
        ))
    }

    /// Build a [`stamp::Plan`] from this bundle plan.
    ///
    /// Collects each action's descriptor and proof witnesses, and the max fee
    /// note with `fee`. The returned plan is ready to prove with
    /// [`stamp::Plan::prove`].
    ///
    /// # Panics
    ///
    /// Panics if `fee` exceeds the max fee note's value.
    #[must_use]
    pub fn stamp_plan(&self, anchor: Anchor, fee: value::Positive) -> stamp::Plan {
        let spends = self
            .spends
            .iter()
            .map(|plan| (plan.descriptor(), plan.theta, plan.rcv))
            .collect();

        let outputs = self
            .outputs
            .iter()
            .map(|plan| (plan.descriptor(), plan.theta, plan.note, plan.rcv))
            .collect();

        stamp::Plan::new(spends, outputs, anchor, self.max_fee_note, fee)
    }

    /// Derive the binding signing key, which is the scalar sum of value
    /// commitment trapdoors, including the max fee note's blind $r$.
    ///
    /// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i \boxplus r$.
    #[must_use]
    pub fn derive_bsk_private(&self) -> private::BindingSigningKey {
        private::BindingSigningKey::from(
            self.iter_actions(|plan| plan.rcv, |plan| plan.rcv)
                .chain([self.max_fee_note.derive_feemax_blind()]),
        )
    }

    /// Sign actions with the provided [`private::SpendAuthorizingKey`] and then
    /// sign the bundle with the [`private::BindingSigningKey`].
    ///
    /// Derives each `alpha` from the action's `theta` and the commitment of
    /// its note.
    ///
    /// To confirm correct application, call [`Bundle::verify_signatures`] on
    /// the return value.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError`] if the planned actions do not balance or an
    /// action cannot be signed.
    pub fn sign<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        sighash: &[u8; 32],
        ask: &private::SpendAuthorizingKey,
    ) -> Result<Bundle<Unproven>, PlanError> {
        let mut authorized: BTreeMap<action::Descriptor, action::Signature> = BTreeMap::new();

        for plan in &self.spends {
            let cm = plan.note.commitment();
            let alpha = plan.theta.randomizer::<effect::Spend>(cm);
            let rsk = ask.derive_action_private(&alpha);
            authorized.insert(plan.descriptor(), rsk.sign(rng, sighash));
        }

        for plan in &self.outputs {
            let cm = plan.note.commitment();
            let alpha = plan.theta.randomizer::<effect::Output>(cm);
            let rsk = private::ActionSigningKey::new(&alpha);
            authorized.insert(plan.descriptor(), rsk.sign(rng, sighash));
        }

        self.apply_signatures(rng, sighash, authorized)
    }

    /// Apply externally-produced action signatures and then sign the bundle
    /// with the [`private::BindingSigningKey`].
    ///
    /// To confirm correct application, call [`Bundle::verify_signatures`] on
    /// the return value.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError`] if the planned actions do not balance or a
    /// descriptor has no supplied signature.
    pub fn apply_signatures<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        sighash: &[u8; 32],
        authorized: BTreeMap<action::Descriptor, action::Signature>,
    ) -> Result<Bundle<Unproven>, PlanError> {
        let value_balance = self
            .value_balance()
            .map_err(|_err| PlanError::BalanceOverflow)?;

        if self.descriptors() != authorized.keys().copied().collect() {
            return Err(PlanError::ActionSigMismatch);
        }

        let binding_sig = self.derive_bsk_private().sign(rng, sighash);

        Ok(Bundle {
            value_balance,
            action_sigs: authorized.into_iter().collect(),
            cv_feemax: self.max_fee_note.cv_feemax(),
            binding_sig,
            memo: self.memo.clone(),
            stamp: Unproven,
        })
    }
}

impl Bundle<Unproven> {
    /// Attach a proof stamp, producing a `Bundle<ProofStamp>`.
    ///
    /// The stamp's tachygram pairs are positional against the actions, which
    /// are in descriptor order. A stamp proven from the same plan holds its
    /// pairs in that order. Only the count is checked here: a stamp from
    /// another plan with the same number of actions attaches, and then fails
    /// verification.
    ///
    /// # Errors
    ///
    /// Returns [`StampError`] if the stamp does not hold one pair per action.
    pub fn stamp(
        self,
        stamp: ProofStamp<stamp::Uncompressed>,
    ) -> Result<Bundle<ProofStamp<stamp::Uncompressed>>, StampError> {
        if stamp.tachygrams.pairs.len() != self.action_sigs.len() {
            return Err(StampError::ActionCountMismatch);
        }

        Ok(Bundle {
            value_balance: self.value_balance,
            action_sigs: self.action_sigs,
            cv_feemax: self.cv_feemax,
            binding_sig: self.binding_sig,
            memo: self.memo,
            stamp,
        })
    }
}

/// Errors while attaching a proof stamp.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum StampError {
    /// The stamp does not hold one tachygram pair per action.
    #[display("stamp does not hold one tachygram pair per action")]
    ActionCountMismatch,
}

impl Bundle<ProofStamp<stamp::Uncompressed>> {
    /// Advance the stamp's anchor along `spans`. The first span must contain
    /// the stamp's anchor, and each later span must contain the previous span's
    /// `anchor_end`. A span contains an anchor if the anchor is its
    /// `anchor_start` or one of its members.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError`] if an action digest cannot be computed, no span
    /// is provided, or a proof-system step fails.
    pub fn lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        adjuncts: &[&Bundle<dyn StampState>],
        spans: Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Result<Self, ProveError> {
        let descriptors: BTreeMap<action::Descriptor, (Tachygram, Tachygram)> = self
            .action_tachygrams()
            .chain(adjuncts.iter().flat_map(|&adj| adj.action_tachygrams()))
            .collect();
        let fee_descriptors: BTreeSet<fee::Descriptor> = iter::once(self.fee_descriptor())
            .chain(adjuncts.iter().map(|&adj| adj.fee_descriptor()))
            .collect();

        let stamp = self
            .stamp
            .lift(rng, app, &descriptors, &fee_descriptors, spans)?;

        Ok(Self { stamp, ..self })
    }
}

impl<P: stamp::Proof> Bundle<ProofStamp<P>> {
    /// Remove the stamp proof, keeping the fee, fee change and tachygram pairs.
    ///
    /// The miner strips the bundle of each transaction an aggregate in its
    /// block lists. Stripping
    /// writes nothing, and the stripped bundle's bytes depend on nothing
    /// outside it.
    #[must_use]
    pub fn strip(self) -> Bundle<StrippedStamp> {
        Bundle {
            value_balance: self.value_balance,
            action_sigs: self.action_sigs,
            cv_feemax: self.cv_feemax,
            binding_sig: self.binding_sig,
            memo: self.memo,
            stamp: StrippedStamp {
                fee: self.stamp.fee,
                tachygrams: self.stamp.tachygrams,
            },
        }
    }

    /// Whether the stamp lists no adjuncts.
    #[must_use]
    pub fn is_autonome(&self) -> bool {
        self.stamp.adjuncts.is_empty()
    }

    /// Whether the stamp lists at least one adjunct.
    #[must_use]
    pub fn is_aggregate(&self) -> bool {
        !self.stamp.adjuncts.is_empty()
    }

    /// Verify that the stamp covers this bundle and the given adjuncts,
    /// returning the covered action and fee digests and the tachygram set
    /// commitment.
    ///
    /// Walks the covered actions and fee descriptors once. The covered
    /// tachygrams are each action's pair and each bundle's fee change, so
    /// $N$ actions and $B$ bundles hold $2N + B$ of them.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyCoverageError`] if the covered tachygrams exceed one
    /// set polynomial, an action, fee or tachygram repeats, a digest cannot be
    /// computed, or the recomputed tachygram set commitment disagrees with the
    /// one the stamp carries.
    pub fn verify_covered(
        &self,
        adjuncts: &[&Bundle<StrippedStamp>],
    ) -> Result<(Vec<ActionDigest>, TachygramSetCommit), VerifyCoverageError> {
        let n_actions = self.action_sigs.len()
            + adjuncts
                .iter()
                .map(|&adj| adj.action_sigs.len())
                .sum::<usize>();
        let n_fees = 1 + adjuncts.len();

        // A set polynomial with n roots has n + 1 coefficients.
        if 2 * n_actions + n_fees + 1 > ProductionRank::num_coeffs() {
            return Err(VerifyCoverageError::TooLarge);
        }

        let mut descriptors = BTreeSet::new();
        let mut fee_entries = BTreeSet::new();
        let mut tachygrams = BTreeSet::new();
        let mut digests = Vec::with_capacity(n_actions + n_fees);

        for action in self
            .actions()
            .chain(adjuncts.iter().flat_map(|&adj| adj.actions()))
        {
            if !descriptors.insert(action.descriptor) {
                return Err(VerifyCoverageError::DuplicateActions);
            }
            for member in <[Tachygram; 2]>::from(action.tg) {
                if !tachygrams.insert(member) {
                    return Err(VerifyCoverageError::DuplicateTachygrams);
                }
            }
            digests.push(action.digest().map_err(VerifyCoverageError::ActionDigest)?);
        }

        for fee_descriptor in iter::once(self.fee_descriptor())
            .chain(adjuncts.iter().map(|&adj| adj.fee_descriptor()))
        {
            if !fee_entries.insert(<[u8; 40]>::from(fee_descriptor)) {
                return Err(VerifyCoverageError::DuplicateFees);
            }
            if !tachygrams.insert(fee_descriptor.fee_change) {
                return Err(VerifyCoverageError::DuplicateTachygrams);
            }
            digests.push(
                fee_descriptor
                    .digest()
                    .map_err(VerifyCoverageError::ActionDigest)?,
            );
        }

        let tachygram_set = tachygrams
            .into_iter()
            .collect::<TachygramSetPoly>()
            .commit();

        if self.stamp.tachygram_set != tachygram_set {
            return Err(VerifyCoverageError::WrongSet);
        }

        Ok((digests, tachygram_set))
    }

    /// Verify the stamp's proof against the given action digests, which
    /// include the digests of covered fee descriptors.
    ///
    /// # Soundness
    ///
    /// The parameter is a multiset: order does not matter, multiplicity does.
    ///
    /// # Errors
    ///
    /// Returns [`ragu_core::Error`] if the proof system fails. A disproved
    /// proof is reported as `Ok(false)`, not an error.
    pub fn verify_proof<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        action_digests: &[ActionDigest],
    ) -> Result<bool, ragu_core::Error> {
        self.stamp
            .verify_proof(rng, app, action_digests.iter().copied())
    }

    /// Verify everything about this bundle, returning the tachygram set
    /// commitment that anchor advancement absorbs. Does not verify any
    /// details about the provided adjuncts.
    ///
    /// - Signatures are valid
    /// - The stamp covers this bundle and the adjuncts
    /// - Proof is correct
    ///
    /// The adjuncts are the stripped bundles the stamp's
    /// [`adjuncts`](ProofStamp::adjuncts) lists, looked up by txid. This method
    /// does not read the list.
    ///
    /// If you need more control, call each verify method directly.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError`] if any of those checks fails, or if the
    /// proof is disproved.
    pub fn verify<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        sighash: &[u8; 32],
        adjuncts: &[&Bundle<StrippedStamp>],
    ) -> Result<TachygramSetCommit, VerificationError> {
        self.verify_signatures(sighash)
            .map_err(VerificationError::Signatures)?;

        let (covered_digests, tachygram_set) = self
            .verify_covered(adjuncts)
            .map_err(VerificationError::Coverage)?;

        if self
            .verify_proof(rng, app, &covered_digests)
            .map_err(VerificationError::Proof)?
        {
            Ok(tachygram_set)
        } else {
            Err(VerificationError::Disproved)
        }
    }
}

impl<S: StampState> Bundle<S> {
    /// Borrow this bundle as a trait object.
    #[must_use]
    pub fn as_dyn(&self) -> &Bundle<dyn StampState>
    where
        S: 'static,
    {
        self
    }

    /// Read a stamped bundle in state `S` from the consensus wire format.
    ///
    /// See the module-level wire format documentation.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails, the state byte does not match `S`,
    /// or any component is not a canonical encoding.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let head = StateByte::read(&mut reader)?;

        if head != S::state_byte() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected tachyonBundleState",
            ));
        }

        Self::read_body(reader)
    }

    /// Read everything after the `tachyonBundleState` byte: value balance,
    /// action descriptors, the max fee note's value commitment, action sigs,
    /// binding sig, memo, and the stamp trailer.
    fn read_body<R: Read>(mut reader: R) -> io::Result<Self> {
        let value_balance = {
            let mut bytes = [0u8; size_of::<i64>()];
            reader.read_exact(&mut bytes)?;
            value::Balance::try_from(i64::from_le_bytes(bytes)).map_err(|_err| {
                io::Error::new(io::ErrorKind::InvalidData, "value balance out of range")
            })
        }?;

        let n_actions =
            usize::try_from(serialization::read_compactsize(&mut reader)?).map_err(|_err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "actions vector length exceeds usize",
                )
            })?;

        // A bundle's two tachygrams per action and its fee change are roots of
        // one set polynomial, which has one more coefficient than roots.
        if 2 * n_actions + 2 > ProductionRank::num_coeffs() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many actions",
            ));
        }

        if n_actions == 0 && value_balance != value::Balance::ZERO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bundle with no actions must have zero value balance",
            ));
        }

        let mut descriptors: Vec<action::Descriptor> = Vec::with_capacity(n_actions);
        for _ in 0..n_actions {
            descriptors.push(action::Descriptor::read(&mut reader)?);
        }

        let cv_feemax = {
            let point = serialization::read_ep_affine(&mut reader)?;
            if point.is_identity() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fee commitment is the identity",
                ));
            }
            value::Commitment::from(point)
        };

        let mut action_sigs = Vec::with_capacity(n_actions);
        for desc in descriptors {
            action_sigs.push((desc, action::Signature::read(&mut reader)?));
        }

        let binding_sig = Signature::read(&mut reader)?;

        // `n_memo` is attacker-controlled up to MAX_COMPACT_SIZE (2^25), so do
        // not pre-allocate. The read is ASSUMED to hit invalid data or EOF
        // before significant problems occur.
        let n_memo =
            usize::try_from(serialization::read_compactsize(&mut reader)?).map_err(|_err| {
                io::Error::new(io::ErrorKind::InvalidData, "memo length exceeds usize")
            })?;

        let mut memo: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 64];
        #[expect(clippy::indexing_slicing, reason = "take is clamped to chunk.len()")]
        while memo.len() < n_memo {
            let take = (n_memo - memo.len()).min(chunk.len());
            reader.read_exact(&mut chunk[..take])?;
            memo.extend_from_slice(&chunk[..take]);
        }

        let stamp = S::read(&mut reader, n_actions)?;

        Ok(Self {
            value_balance,
            action_sigs,
            cv_feemax,
            binding_sig,
            memo,
            stamp,
        })
    }

    /// Write the bundle in the consensus wire format: the
    /// `tachyonBundleState` byte for `S`, the bundle body, and the stamp.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails or a count exceeds what a
    /// compactsize can hold.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        S::state_byte().write(&mut writer)?;

        writer.write_all(&i64::from(self.value_balance).to_le_bytes())?;

        let n_actions = u64::try_from(self.action_sigs.len()).map_err(|_err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "actions vector length exceeds u64",
            )
        })?;

        serialization::write_compactsize(&mut writer, n_actions)?;
        for &(desc, _) in &self.action_sigs {
            desc.write(&mut writer)?;
        }

        serialization::write_ep_affine(&mut writer, &self.cv_feemax.into())?;

        for &(_, sig) in &self.action_sigs {
            sig.write(&mut writer)?;
        }

        self.binding_sig.write(&mut writer)?;

        let n_memo = u64::try_from(self.memo.len()).map_err(|_err| {
            io::Error::new(io::ErrorKind::InvalidData, "memo length exceeds u64")
        })?;

        serialization::write_compactsize(&mut writer, n_memo)?;
        writer.write_all(&self.memo)?;

        self.stamp.write(&mut writer)
    }

    /// Tachyon's contribution to the transaction `auth_digest`.
    ///
    /// Commits the action signatures, the binding signature, and
    /// `hStampTachyon`, which covers `vTachygrams`, the fee and
    /// `hStampProofTachyon`. See [`blake2b::bundle_auth_digest`] and
    /// [`blake2b::stamp_digest`]. The memo is absent here because it is
    /// effecting data, committed by [`Self::commitment`].
    #[must_use]
    pub fn auth_digest(&self) -> [u8; 32] {
        let action_sigs: Vec<[u8; 64]> = self.action_sigs.iter().map(|&(_, sig)| sig).collect();
        let binding_sig: [u8; 64] = self.binding_sig.0.into();
        let stamp_digest = blake2b::stamp_digest(
            &Vec::<[u8; 32]>::from(self.stamp.tachygrams()),
            u64::from(self.stamp.fee()),
            &self.stamp.stamp_proof_digest(),
        );

        blake2b::bundle_auth_digest(
            S::state_byte().into(),
            &action_sigs,
            &binding_sig,
            &stamp_digest,
        )
    }
}

/// A Tachyon bundle in one of its valid wire states.
///
/// The `Unproven` intermediate state is outside this enum because it has no
/// wire representation.
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
#[derive(Clone, Debug, From, IsVariant, TryInto)]
pub enum TachyonBundle {
    /// No bundle.
    NoBundle,
    /// A bundle with its own proof (autonome or aggregate).
    Proven(Bundle<ProofStamp<stamp::Compressed>>),
    /// A bundle with no internal proof (adjunct).
    Adjunct(Bundle<StrippedStamp>),
}

impl PartialEq for TachyonBundle {
    fn eq(&self, other: &Self) -> bool {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => other.is_no_bundle(),
            Self::Proven(ref bundle) => {
                other.is_proven()
                    && bundle.commitment() == other.commitment()
                    && bundle.auth_digest() == other.auth_digest()
            },
            Self::Adjunct(ref bundle) => {
                other.is_adjunct()
                    && bundle.commitment() == other.commitment()
                    && bundle.auth_digest() == other.auth_digest()
            },
        }
    }
}

impl PartialOrd for TachyonBundle {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            self.commitment()
                .cmp(&other.commitment())
                .then(self.auth_digest().cmp(&other.auth_digest())),
        )
    }
}

impl TachyonBundle {
    /// Borrow the inner bundle as a trait object, if it exists.
    #[must_use]
    pub fn as_dyn(&self) -> Option<&Bundle<dyn StampState>> {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => None,
            Self::Proven(ref bundle) => Some(bundle),
            Self::Adjunct(ref bundle) => Some(bundle),
        }
    }

    /// Read any Tachyon bundle from the consensus wire format, dispatching
    /// on the `tachyonBundleState` byte.
    ///
    /// Decodes `0x00` (non-tachyon) as [`Self::NoBundle`], `0x01` as a
    /// proof-stamped bundle, and `0x02` as a stripped bundle;
    /// rejects any other byte.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails, the state byte is none of those
    /// three, or any component is not a canonical encoding.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let state = StateByte::read(&mut reader)?;

        Ok(match state {
            StateByte::NoBundle => Self::NoBundle,
            StateByte::ProofStamped => Self::Proven(Bundle::read_body(&mut reader)?),
            StateByte::Stripped => Self::Adjunct(Bundle::read_body(&mut reader)?),
        })
    }

    /// Write any Tachyon bundle in the consensus wire format, dispatching on
    /// the variant.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => StateByte::NoBundle.write(writer),
            Self::Proven(ref stamped) => stamped.write(writer),
            Self::Adjunct(ref stamped) => stamped.write(writer),
        }
    }

    /// Tachyon's contribution to the transaction `auth_digest`, dispatching
    /// on the variant.
    #[must_use]
    pub fn auth_digest(&self) -> [u8; 32] {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => *blake2b::AUTH_DIGEST_NO_BUNDLE,
            Self::Proven(ref stamped) => stamped.auth_digest(),
            Self::Adjunct(ref stamped) => stamped.auth_digest(),
        }
    }

    /// Tachyon's contribution to the transaction sighash, dispatching on the
    /// variant.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => *blake2b::COMMIT_NO_BUNDLE,
            Self::Proven(ref stamped) => stamped.commitment(),
            Self::Adjunct(ref stamped) => stamped.commitment(),
        }
    }

    /// Whether this bundle has a proof stamp listing at least one adjunct.
    #[must_use]
    pub fn is_aggregate(&self) -> bool {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => false,
            Self::Proven(ref stamped) => stamped.is_aggregate(),
            Self::Adjunct(ref _stamped) => false,
        }
    }

    /// Whether this bundle has a proof stamp listing no adjuncts.
    #[must_use]
    pub fn is_autonome(&self) -> bool {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => false,
            Self::Proven(ref stamped) => stamped.is_autonome(),
            Self::Adjunct(ref _stamped) => false,
        }
    }
}

/// A binding signature (RedPallas over the Binding group).
///
/// Proves the signer knew the opening $\mathsf{bsk}$ of the Pedersen
/// commitment $\mathsf{bvk}$ to value 0. By the **binding property**
/// of the commitment scheme, it is infeasible to find
/// $(v^\ast, \mathsf{bsk}^\prime)$ such that
/// $\mathsf{bvk} = \text{ValueCommit}_{\mathsf{bsk}^\prime}(v^\ast)$ for
/// $v^\ast \neq 0$, so value balance is enforced.
///
/// The signed message is the transaction sighash, a transaction-wide
/// digest computed at the transaction layer. The validator verifies
/// `binding_sig` against it under $\mathsf{bvk}$.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Signature(pub(crate) reddsa::Signature<reddsa::BindingAuth>);

impl Signature {
    /// Read a binding signature from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let sig = serialization::read_binding_sig(&mut reader)?;
        Ok(Self(sig))
    }

    /// Write a binding signature to the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_binding_sig(&mut writer, &self.0)?;
        Ok(())
    }
}
