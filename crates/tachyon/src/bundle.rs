//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by stamp state `S: StampState`.
//! Its body is constant through stamp transformations; only the stamp changes.
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
//! | `nMemoTachyon`        | compactsize          | memo length, `0` when absent             |
//! | `vMemoTachyon`        | nMemoTachyon bytes   | opaque recipient-directed payload        |
//! | `vActionSigsTachyon`  | 64 * nActionsTachyon | authorization per action over tx sighash |
//! | `bindingSigTachyon`   | 64 bytes             | binding over tx sighash                  |
//! | `vActionTachygramsTachyon` | 64 * nActionsTachyon | each action's tachygram pair         |
//! | `vFeeTachyon`        | LE64                 | fee, at most `MAX_MONEY`                 |
//! | `cmChangeTachyon`    | 32 bytes             | fee change note commitment              |
//!
//! The fields are phase-ordered: effecting data through the memo, then signing
//! data, then proving data. One action count frames all three action vectors.
//! Each pair's two canonical field elements may occur in either order. The
//! prover writes the smaller first, revealing neither member's role. All pair
//! members and `cmChangeTachyon` must be distinct.
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
//! | Name                    | Format                   | Description                                |
//! | ----------------------- | ------------------------ | ------------------------------------------ |
//! | `anchorTachyon`         | 32 bytes                 | pool state reference                       |
//! | `cTachygrams`           | 32 bytes                 | commitment to the covered tachygram union  |
//! | `nAdjunctsTachyon`      | compactSize              | number of adjuncts, `0` for an autonome    |
//! | `vAdjunctsTachyon`      | 32 * nAdjunctsTachyon    | txids of the other covered transactions    |
//! | `sizeProofTachyon`      | compactSize              | length of `proofTachyon` in bytes          |
//! | `proofTachyon`          | `byte[sizeProofTachyon]` | the Ragu stamp proof                       |
//!
//! `cTachygrams` is carried rather than derived, so full validation must
//! confirm it against every covered bundle's pairs and fee change. Anchor
//! advancement then reads the point instead of rebuilding it.
//!
//! `vAdjunctsTachyon` is strictly ascending by bytewise comparison, so it holds
//! no repeat. Every adjunct holds at least its fee change, so a stamp with
//! `2 * nActionsTachyon + nAdjunctsTachyon + 1 > 8191` is rejected after the
//! whole trailer is read. The standalone stamp reader checks
//! `nAdjunctsTachyon + 1 <= 8191` before reading the adjunct list.
//!
//! Consensus carries [`Compressed`](stamp::Compressed) proofs, and
//! `Bundle<ProofStamp<Uncompressed>>` uses the same `0x01` layout with the
//! uncompressed length while stamps are merged and lifted outside consensus.
//!
//! ## Stripped stamp
//!
//! When `tachyonBundleState == 2`, the stamp trailer is empty.
//!
//! The transaction `auth_digest` contribution commits either stamp as
//! `hStampTachyon`, over the adjunct list and `hStampProofTachyon`. A stripped
//! stamp has neither and takes the empty-input stamp hash. See
//! [`blake2b::stamp_digest`].

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
use udon::{curve::Affine as _, field::Field as _};

use crate::{
    ActionDigest, Note, Tachygram, TachygramSetCommit, TachygramSetPoly, action,
    digest::blake2b,
    fee,
    keys::{private, public},
    pasta::Fp,
    primitives::{Anchor, effect},
    reddsa, serialization,
    stamp::{
        self, ProofStamp, StampState, StrippedStamp,
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
    /// Bundle with a [`ProofStamp`].
    ProofStamp = 0b0000_0001u8,
    /// Bundle with a [`StrippedStamp`].
    StrippedStamp = 0b0000_0010u8,
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
            0b0000_0001u8 => Ok(Self::ProofStamp),
            0b0000_0010u8 => Ok(Self::StrippedStamp),
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

/// A Tachyon transaction bundle parameterized by bundle state `S`.
#[derive(Clone, Debug)]
pub struct Bundle<S: StampState + ?Sized> {
    /// Net value of spends minus outputs and max fee.
    pub value_balance: value::Balance,

    /// Action descriptors in wire order, with the same length as `action_auth`.
    pub actions: Vec<action::Descriptor>,

    /// Each action's signature and tachygram pair, in the same wire order as
    /// `actions`. This has the same length as `actions`.
    pub action_auth: Vec<(action::Signature, (Tachygram, Tachygram))>,

    /// The max fee note's value commitment and the fee paid by this bundle.
    pub fee: fee::Descriptor,

    /// The fee change note commitment.
    pub fee_auth: Tachygram,

    /// Binding signature over the transaction sighash.
    pub binding_sig: Signature,

    /// Opaque recipient-directed payload, empty when absent.
    pub memo: Vec<u8>,

    /// Bundle stamp, kept last to permit a dynamically sized stamp state.
    pub stamp: S,
}

impl<S: StampState + 'static> PartialEq for Bundle<S> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment() == other.commitment() && self.auth_digest() == other.auth_digest()
    }
}

impl<S: StampState + ?Sized> Bundle<S> {
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
        let descriptors: Vec<[u8; 64]> = self.actions.iter().copied().collect();
        blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&descriptors),
            self.value_balance.into(),
            &self.fee.cv_feemax.into(),
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
            self.actions
                .iter()
                .map(|desc| desc.cv)
                .chain([self.fee.cv_feemax]),
            self.value_balance,
        );

        // 2. Verify binding signature
        bvk.verify(sighash, &self.binding_sig)
            .map_err(|_err| SignatureError::Binding(self.binding_sig))?;

        // 3. Verify each action signature
        for (action, &(sig, _)) in self.actions.iter().zip(&self.action_auth) {
            action
                .rk
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
    /// The actions are not unique.
    #[display("actions are not unique")]
    DuplicateActions,
    /// The fees are not unique.
    #[display("fees are not unique")]
    DuplicateFees,
    /// A tachygram repeats among the covered bundles.
    #[display("tachygrams are not unique")]
    DuplicateTachygrams,
    /// The covered bundles' tachygrams do not reproduce the stamp's set
    /// commitment, or number more than one set polynomial has roots. The
    /// stamp does not cover exactly this bundle and these adjuncts as given.
    #[display("tachygrams do not reproduce the set commitment")]
    WrongTachygramSet,
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
    /// This is the prover-side set. Contrast [`Bundle::actions`], the wire
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
    /// Returns the descriptor-keyed action signatures and the binding
    /// signature.
    ///
    /// # Errors
    ///
    /// Returns [`value::OutOfRange`] if the planned balance is out of range.
    pub fn sign<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        sighash: &[u8; 32],
        ask: &private::SpendAuthorizingKey,
    ) -> Result<(BTreeMap<action::Descriptor, action::Signature>, Signature), value::OutOfRange>
    {
        self.value_balance()?;
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

        Ok((authorized, self.derive_bsk_private().sign(rng, sighash)))
    }

    /// Apply externally-produced action signatures and then sign the bundle
    /// with the [`private::BindingSigningKey`].
    ///
    /// Returns the descriptor-keyed action signatures and the binding
    /// signature.
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
    ) -> Result<(BTreeMap<action::Descriptor, action::Signature>, Signature), PlanError> {
        self.value_balance()
            .map_err(|_err| PlanError::BalanceOverflow)?;

        if self.descriptors() != authorized.keys().copied().collect() {
            return Err(PlanError::ActionSigMismatch);
        }
        let binding_sig = self.derive_bsk_private().sign(rng, sighash);

        Ok((authorized, binding_sig))
    }

    /// Verify the binding signature and each keyed action signature.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError`] if any signature is invalid.
    ///
    /// # Panics
    ///
    /// Panics if the plan's balance is out of range or the signature keys do
    /// not match the plan.
    pub fn verify_signatures(
        &self,
        sighash: &[u8; 32],
        signatures: &(BTreeMap<action::Descriptor, action::Signature>, Signature),
    ) -> Result<(), SignatureError> {
        let action_sigs = &signatures.0;
        let binding_sig = &signatures.1;
        self.assert_signing_descriptors(action_sigs);
        let bvk = public::BindingVerificationKey::derive(
            action_sigs
                .keys()
                .map(|desc| desc.cv)
                .chain([self.max_fee_note.cv_feemax()]),
            self.signed_balance(),
        );
        bvk.verify(sighash, binding_sig)
            .map_err(|_err| SignatureError::Binding(*binding_sig))?;
        for (desc, sig) in action_sigs {
            desc.rk
                .verify(sighash, sig)
                .map_err(|_err| SignatureError::Action(*sig))?;
        }
        Ok(())
    }

    fn assert_signing_descriptors(
        &self,
        action_sigs: &BTreeMap<action::Descriptor, action::Signature>,
    ) {
        assert!(
            self.descriptors().iter().eq(action_sigs.keys()),
            "action descriptors do not match"
        );
    }

    #[expect(clippy::expect_used, reason = "signing checks the planned balance")]
    fn signed_balance(&self) -> value::Balance {
        self.value_balance().expect("planned balance is in range")
    }

    /// Assemble the bundle from signatures and independently produced proof
    /// data.
    ///
    /// # Panics
    ///
    /// Panics if the plan, signature and tachygram pair keys differ or the
    /// plan's balance is out of range.
    #[must_use]
    #[expect(
        clippy::type_complexity,
        reason = "takes the prover's outputs as returned"
    )]
    pub fn assemble(
        &self,
        (action_sigs, binding_sig): (BTreeMap<action::Descriptor, action::Signature>, Signature),
        (stamp, pairs, cm_change, fee): (
            ProofStamp<stamp::Uncompressed>,
            BTreeMap<action::Descriptor, (Tachygram, Tachygram)>,
            Tachygram,
            value::Positive,
        ),
    ) -> Bundle<ProofStamp<stamp::Uncompressed>> {
        assert!(
            self.descriptors().iter().eq(action_sigs.keys()) && action_sigs.keys().eq(pairs.keys()),
            "action descriptors do not match"
        );
        let (actions, action_auth) = action_sigs
            .into_iter()
            .zip(pairs)
            .map(|((desc, sig), (_, pair))| (desc, (sig, pair)))
            .unzip();
        Bundle {
            actions,
            action_auth,
            value_balance: self.signed_balance(),
            fee: fee::Descriptor {
                cv_feemax: self.max_fee_note.cv_feemax(),
                v_fee: fee,
            },
            fee_auth: cm_change,
            binding_sig,
            memo: self.memo.clone(),
            stamp,
        }
    }
}

impl Bundle<ProofStamp<stamp::Uncompressed>> {
    /// Advance the stamp's anchor along `spans`. The first span must contain
    /// the stamp's anchor, and each later span must contain the previous span's
    /// `anchor_end`. A span contains an anchor if the anchor is its
    /// `anchor_start` or one of its members.
    ///
    /// # Errors
    ///
    /// Returns [`ragu_core::Error`] if a proof-system operation fails.
    /// Empty `spans` leave the bundle unchanged.
    ///
    /// # Panics
    ///
    /// Panics when digesting a hand-built bundle holding an identity `cv` or
    /// `rk`.
    pub fn lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        adjuncts: &[&Bundle<dyn StampState>],
        spans: Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Result<Self, ragu_core::Error> {
        if spans.is_empty() {
            return Ok(self);
        }
        let covered = iter::once(self.as_dyn()).chain(adjuncts.iter().copied());
        let mut descriptors = BTreeMap::new();
        let mut fee_descriptors = BTreeMap::new();
        for bundle in covered {
            descriptors.extend(
                bundle
                    .actions
                    .iter()
                    .copied()
                    .zip(bundle.action_auth.iter().map(|&(_, pair)| pair)),
            );
            fee_descriptors.insert(bundle.fee, bundle.fee_auth);
        }
        let stamp = self
            .stamp
            .lift(rng, app, &descriptors, &fee_descriptors, spans)?;

        Ok(Self { stamp, ..self })
    }
}

impl<P: stamp::Proof> Bundle<ProofStamp<P>> {
    /// Read a proof-stamped bundle, including the combined coverage bound.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid encodings, a wrong state byte, or too many
    /// actions and adjuncts for one tachygram set polynomial.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        if StateByte::read(&mut reader)? != StateByte::ProofStamp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected tachyonBundleState",
            ));
        }
        Self::read_proof_body(reader)
    }

    fn read_proof_body<R: Read>(reader: R) -> io::Result<Self> {
        let bundle = Self::read_body(reader)?;
        if 2 * bundle.actions.len() + bundle.stamp.adjuncts.len() + 1
            > ProductionRank::num_coeffs() - 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many adjuncts",
            ));
        }
        Ok(bundle)
    }

    /// Remove the stamp proof, keeping the fee, fee change and tachygram pairs.
    ///
    /// The miner strips the bundle of each transaction an aggregate in its
    /// block lists. Stripping writes nothing, and the stripped bundle's bytes
    /// depend on nothing outside it.
    #[must_use]
    pub fn strip(self) -> Bundle<StrippedStamp> {
        Bundle {
            actions: self.actions,
            action_auth: self.action_auth,
            value_balance: self.value_balance,
            fee: self.fee,
            fee_auth: self.fee_auth,
            binding_sig: self.binding_sig,
            memo: self.memo,
            stamp: StrippedStamp,
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
    /// Returns [`VerifyCoverageError`] if an action, fee or tachygram repeats,
    /// or the covered tachygrams number more than one set polynomial has roots
    /// or do not reproduce the tachygram set commitment the stamp carries.
    ///
    /// # Panics
    ///
    /// Panics when digesting a hand-built bundle holding an identity `cv` or
    /// `rk`.
    pub fn verify_covered(
        &self,
        adjuncts: &[&Bundle<StrippedStamp>],
    ) -> Result<(Vec<ActionDigest>, TachygramSetCommit), VerifyCoverageError> {
        let n_actions =
            self.actions.len() + adjuncts.iter().map(|&adj| adj.actions.len()).sum::<usize>();
        let n_fees = 1 + adjuncts.len();

        // A set polynomial with n roots has n + 1 coefficients, so no
        // commitment matches a larger set.
        if 2 * n_actions + n_fees > ProductionRank::num_coeffs() - 1 {
            return Err(VerifyCoverageError::WrongTachygramSet);
        }

        let covered = iter::once((&self.actions, &self.action_auth, self.fee, self.fee_auth))
            .chain(
                adjuncts
                    .iter()
                    .map(|adj| (&adj.actions, &adj.action_auth, adj.fee, adj.fee_auth)),
            );

        let mut covered_descriptors = BTreeSet::new();
        let mut fee_entries = BTreeSet::new();
        let mut covered_tachygrams = BTreeSet::new();
        let mut digests = Vec::new();

        for (actions, action_auth, fee_descriptor, cm_change) in covered {
            for (&descriptor, &(_, pair)) in actions.iter().zip(action_auth) {
                if !covered_descriptors.insert(descriptor) {
                    return Err(VerifyCoverageError::DuplicateActions);
                }
                for tachygram in <[Tachygram; 2]>::from(pair) {
                    if !covered_tachygrams.insert(tachygram) {
                        return Err(VerifyCoverageError::DuplicateTachygrams);
                    }
                }
                digests.push(descriptor.digest(pair));
            }
            if !fee_entries.insert(<[u8; 40]>::from(fee_descriptor)) {
                return Err(VerifyCoverageError::DuplicateFees);
            }
            if !covered_tachygrams.insert(cm_change) {
                return Err(VerifyCoverageError::DuplicateTachygrams);
            }
            digests.push(fee_descriptor.digest(cm_change));
        }

        let tachygram_set = covered_tachygrams
            .into_iter()
            .collect::<TachygramSetPoly>()
            .commit();

        if self.stamp.tachygram_set != tachygram_set {
            return Err(VerifyCoverageError::WrongTachygramSet);
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
    ///
    /// # Panics
    ///
    /// Panics when digesting a hand-built bundle holding an identity `cv` or
    /// `rk`.
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

    /// Read everything after the `tachyonBundleState` byte: value balance,
    /// action descriptors, max fee commitment, memo, signatures, tachygram
    /// pairs, fee, change, and the stamp trailer.
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
        if 2 * n_actions + 1 > ProductionRank::num_coeffs() - 1 {
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

        let mut actions: Vec<action::Descriptor> = Vec::new();
        for _ in 0..n_actions {
            actions.push(action::Descriptor::read(&mut reader)?);
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

        let mut signatures: Vec<action::Signature> = Vec::new();
        for _ in 0..n_actions {
            signatures.push(action::Signature::read(&mut reader)?);
        }
        let binding_sig = Signature::read(&mut reader)?;

        let mut action_auth = Vec::new();
        let mut seen = BTreeSet::new();
        for sig in signatures {
            let pair = (Tachygram::read(&mut reader)?, Tachygram::read(&mut reader)?);
            seen.insert(pair.0);
            seen.insert(pair.1);
            action_auth.push((sig, pair));
        }
        let fee = {
            let mut bytes = [0u8; size_of::<u64>()];
            reader.read_exact(&mut bytes)?;
            value::Positive::try_from(u64::from_le_bytes(bytes))
                .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "fee out of range"))?
        };
        let cm_change = Tachygram::read(&mut reader)?;
        seen.insert(cm_change);
        if seen.len() != 2 * n_actions + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tachygrams are not unique",
            ));
        }

        let stamp = S::read(&mut reader)?;

        Ok(Self {
            value_balance,
            actions,
            action_auth,
            fee: fee::Descriptor {
                cv_feemax,
                v_fee: fee,
            },
            fee_auth: cm_change,
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

        let n_actions = u64::try_from(self.actions.len()).map_err(|_err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "actions vector length exceeds u64",
            )
        })?;

        serialization::write_compactsize(&mut writer, n_actions)?;
        for action in &self.actions {
            action.write(&mut writer)?;
        }

        serialization::write_ep_affine(&mut writer, &self.fee.cv_feemax.into())?;

        let n_memo = u64::try_from(self.memo.len()).map_err(|_err| {
            io::Error::new(io::ErrorKind::InvalidData, "memo length exceeds u64")
        })?;

        serialization::write_compactsize(&mut writer, n_memo)?;
        writer.write_all(&self.memo)?;

        for &(sig, _) in &self.action_auth {
            sig.write(&mut writer)?;
        }
        self.binding_sig.write(&mut writer)?;

        for &(_, pair) in &self.action_auth {
            pair.0.write(&mut writer)?;
            pair.1.write(&mut writer)?;
        }
        writer.write_all(&u64::from(self.fee.v_fee).to_le_bytes())?;
        self.fee_auth.write(&mut writer)?;

        self.stamp.write(&mut writer)
    }

    /// Tachyon's contribution to the transaction `auth_digest`.
    ///
    /// Commits each action's signature and pair, the fee, fee change,
    /// binding signature and `hStampTachyon`. See
    /// [`blake2b::bundle_auth_digest`] and
    /// [`blake2b::stamp_digest`]. The memo is absent here because it is
    /// effecting data, committed by [`Self::commitment`].
    #[must_use]
    pub fn auth_digest(&self) -> [u8; 32] {
        let action_auth: Vec<[u8; 128]> = self
            .action_auth
            .iter()
            .map(|&(sig, pair)| {
                let mut record = [0u8; 128];
                record[..64].copy_from_slice(&<[u8; 64]>::from(sig.0));
                record[64..96].copy_from_slice(&Fp::from(pair.0).to_bytes());
                record[96..].copy_from_slice(&Fp::from(pair.1).to_bytes());
                record
            })
            .collect();
        let binding_sig: [u8; 64] = self.binding_sig.0.into();

        blake2b::bundle_auth_digest(
            S::state_byte().into(),
            &action_auth,
            self.fee.v_fee.into(),
            &Fp::from(self.fee_auth).to_bytes(),
            &binding_sig,
            &self.stamp.stamp_digest(),
        )
    }
}

impl Bundle<StrippedStamp> {
    /// Read a stripped bundle whose stamp trailer is empty.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid encodings or a wrong state byte.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        if StateByte::read(&mut reader)? != StateByte::StrippedStamp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected tachyonBundleState",
            ));
        }
        Self::read_body(reader)
    }
}

/// A Tachyon bundle in one of its valid wire states.
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
            StateByte::ProofStamp => Self::Proven(Bundle::read_proof_body(&mut reader)?),
            StateByte::StrippedStamp => Self::Adjunct(Bundle::read_body(&mut reader)?),
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
