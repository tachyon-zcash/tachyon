//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by bundle state `S: BundleState`.
//! Actions are constant through state transitions; only the stamp changes.
//!
//! - `Bundle<ProofStamp>`: self-contained bundle with a proof stamp
//! - `Bundle<PointerStamp>`: proof stamp replaced by a pointer stamp naming the
//!   covering aggregate
//! - [`TachyonBundle`]: enum of the on-wire forms for mixed contexts
//!
//! # Consensus wire format
//!
//! The first byte `tachyonBundleState` selects one of three bundle states:
//!
//! | value         | state         | bundle contents                       |
//! | ------------- | ------------- | ------------------------------------- |
//! | `0b0000_0000` | non-tachyon   | no bundle                             |
//! | `0b0000_0001` | proof stamp   | bundle with anchor, tachygrams, proof |
//! | `0b0000_0010` | pointer stamp | bundle with aggregate's wtxid         |
//! | `...`         | *reserved*    | *n/a*                                 |
//!
//! Any other byte is invalid. Pointer-stamped innocents and adjuncts share
//! the same wire layout (both write `0x02` + body + a nonzero 64-byte `wtxid`
//! naming the covering aggregate).
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
//! | `valueBalanceTachyon` | i64                  | net value of tachyon actions             |
//! | `nActionsTachyon`     | compactsize          | number of tachyon actions                |
//! | `vActionsTachyon`     | 64 * nActionsTachyon | (cv: 32 bytes, rk: 32 bytes)             |
//! | `vActionSigsTachyon`  | 64 * nActionsTachyon | authorization per action over tx sighash |
//! | `bindingSigTachyon`   | 64 bytes             | binding over tx sighash                  |
//! | `nMemoTachyon`        | compactsize          | memo length, `0` when absent             |
//! | `vMemoTachyon`        | nMemoTachyon bytes   | opaque recipient-directed payload        |
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
//! | Name                   | Format               | Description                              |
//! | ---------------------- | -------------------- | ---------------------------------------- |
//! | `hStampActionsTachyon` | 32 bytes             | BLAKE2b digest of the covered actions    |
//! | `anchorTachyon`        | 32 bytes             | pool state reference                     |
//! | `cTachygrams`          | 32 bytes             | commitment to the tachygrams below       |
//! | `nTachygrams`          | compactsize          | number of tachygrams                     |
//! | `vTachygrams`          | 32 * nTachygrams     | tachygrams for this proof                |
//! | `proofTachyon`         | PROOF_SIZE blob      | serialized proof of fixed size           |
//!
//! `cTachygrams` is carried rather than derived, so full validation must
//! confirm it against `vTachygrams`. Anchor advancement then reads the point
//! instead of rebuilding it.
//!
//! ## Pointer stamp
//!
//! When `tachyonBundleState == 2`, the bundle carries a pointer stamp.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `tachyonAggregateId`  | 64 bytes             | wtxid of the relevant aggregate          |
//!
//! The transaction `auth_digest` contribution commits either stamp as a
//! 64-byte value: the pointer stamp's `wtxid` directly, or
//! `hStampActionsTachyon || stamp_data_digest` for a proof stamp.

use alloc::{collections::BTreeSet, vec::Vec};
use core::cmp::Ordering;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, From, IsVariant, PartialEq, TryInto};
use rand_core::CryptoRng;

use crate::{
    ActionDigest, ActionDigestError, TachygramSetCommit, TachygramSetPoly,
    action::{self, Action},
    digest::blake2b,
    keys::public,
    primitives::AnchorSetPoly,
    reddsa, serialization,
    stamp::{
        AggregateIdError, PointerStamp, ProofStamp, ProveError, StampState, Unproven, proof::pool,
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
    /// Pointer stamped bundle.
    PointerStamped = 0b0000_0010u8,
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
            0b0000_0010u8 => Ok(Self::PointerStamped),
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
    impl Sealed for super::ProofStamp {}
    impl Sealed for super::PointerStamp {}
}

/// Sealed trait constraining bundle state types.
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
pub trait BundleState: sealed::Sealed {}

impl<T: sealed::Sealed> BundleState for T {}

/// A Tachyon transaction bundle parameterized by bundle state `S`.
#[derive(Clone, Debug)]
pub struct Bundle<S: BundleState + ?Sized> {
    /// Net value of spends minus outputs (plaintext integer).
    pub value_balance: value::Balance,

    /// Actions (cv, rk, sig).
    pub actions: Vec<Action>,

    /// Binding signature over the transaction sighash.
    pub binding_sig: Signature,

    /// Opaque recipient-directed payload, empty when absent.
    pub memo: Vec<u8>,

    /// Bundle state: `Unproven`, `ProofStamp`, or `PointerStamp`.
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
        self.actions.iter().map(Action::descriptor)
    }

    /// Digest the bundle's effecting data.
    ///
    /// This contributes to the transaction sighash. The stamp is excluded
    /// because it is considered authorizing data, and is malleable during
    /// aggregation. The memo is included, so a miner cannot strip the payload
    /// and leave the block committing to the same transaction.
    ///
    /// The digest binds actions in wire order and is therefore sensitive to
    /// their ordering.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let descriptors: Vec<[u8; 64]> = self.descriptors().collect();
        blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&descriptors),
            self.value_balance.into(),
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
        let bvk = public::BindingVerificationKey::derive(&self.actions, self.value_balance);

        // 2. Verify binding signature
        bvk.verify(sighash, &self.binding_sig)
            .map_err(|_err| SignatureError::Binding(self.binding_sig))?;

        // 3. Verify each action signature
        for action in &self.actions {
            action
                .rk
                .verify(sighash, &action.sig)
                .map_err(|_err| SignatureError::Action(action.sig))?;
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
    /// The stamp on this bundle does not claim to cover these actions.
    #[display("stamp on this bundle does not claim to cover these actions")]
    StampActionsMismatch,
}

/// Errors during tachygram verification.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum VerifyTachygramsError {
    /// The stamp publishes a number of tachygrams other than two per action.
    #[display("stamp does not publish two tachygrams per covered action")]
    WrongArity,
    /// The stamp's tachygrams do not reproduce the stamp's set commitment.
    #[display("tachygrams do not reproduce the set commitment")]
    WrongSet,
}

/// Errors during adjunct pointer verification.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum VerifyPointersError {
    /// The pointer of an adjunct is not the expected aggregate id.
    #[display("stamp on an adjunct does not match the expected aggregate id")]
    AdjunctPointerMismatch,
    /// The adjunct is not in the expected state.
    #[display("stamp on an adjunct does not contain a valid pointer")]
    AdjunctPointerInvalid(AggregateIdError),
}

/// Errors during bundle verification.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum VerificationError {
    /// The bundle signatures did not verify.
    #[display("signature verification error: {_0}")]
    Signatures(SignatureError),
    /// An error occurred while verifying the adjunct pointers.
    #[display("adjunct pointer verification error: {_0}")]
    Pointers(VerifyPointersError),
    /// An error occurred while verifying the coverage.
    #[display("coverage verification error: {_0}")]
    Coverage(VerifyCoverageError),
    /// An error occurred while collecting the action digest set.
    #[display("action verification error: {_0}")]
    Actions(ActionDigestError),
    /// An error occurred while verifying the tachygram set.
    #[display("tachygrams verification error: {_0}")]
    Tachygrams(VerifyTachygramsError),
    /// An error occurred while verifying the proof.
    #[display("proof verification error: {_0}")]
    Proof(ragu_core::Error),
    /// The proof did not verify.
    #[display("proof did not verify")]
    Disproved,
}

impl Bundle<Unproven> {
    /// Attach a proof stamp, producing a `Bundle<ProofStamp>`.
    #[must_use]
    pub fn stamp(self, stamp: ProofStamp) -> Bundle<ProofStamp> {
        Bundle {
            actions: self.actions,
            value_balance: self.value_balance,
            binding_sig: self.binding_sig,
            memo: self.memo,
            stamp,
        }
    }
}

impl Bundle<ProofStamp> {
    /// Replace the stamp with a wtxid pointer to a covering aggregate.
    #[must_use]
    pub fn strip(self, wtxid: PointerStamp) -> Bundle<PointerStamp> {
        Bundle {
            actions: self.actions,
            value_balance: self.value_balance,
            binding_sig: self.binding_sig,
            memo: self.memo,
            stamp: wtxid,
        }
    }

    /// Advance the stamp's anchor along `spans`. Each entry is an anchor span
    /// and its members polynomial. The first span must contain the stamp's
    /// anchor, and each later span must contain the previous span's
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
        adjuncts: &[&Bundle<dyn StampState>],
        spans: Vec<(ragu::Pcd<pool::AnchorSpan>, AnchorSetPoly)>,
    ) -> Result<Self, ProveError> {
        let descriptors: BTreeSet<action::Descriptor> = self
            .descriptors()
            .chain(adjuncts.iter().flat_map(|&adj| adj.descriptors()))
            .collect();

        let stamp = self.stamp.lift(rng, &descriptors, spans)?;

        Ok(Self { stamp, ..self })
    }

    /// Confirm `hStampActionsTachyon` represents the combined actions of this
    /// bundle and the given bundles.
    #[must_use]
    pub fn is_covering(&self, others: &[&Bundle<dyn StampState>]) -> bool {
        let own_descs = self.descriptors();
        let other_descs = others.iter().flat_map(|&adjunct| adjunct.descriptors());

        self.stamp
            .is_covering(own_descs.into_iter().chain(other_descs))
    }

    /// Confirm `hStampActionsTachyon` represents this bundle's actions.
    #[must_use]
    pub fn is_autonome(&self) -> bool {
        self.is_covering(&[])
    }

    /// Confirm `hStampActionsTachyon` does not represent this bundle's actions.
    #[must_use]
    pub fn is_aggregate(&self) -> bool {
        !self.is_covering(&[])
    }

    /// Verify the stamp's coverage against this bundle's own actions combined
    /// with the given adjunct descriptors, returning the descriptors covered.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyCoverageError`] if a descriptor repeats, an action
    /// digest cannot be computed, or the recomputed coverage disagrees with
    /// the one the stamp carries.
    pub fn verify_coverage(
        &self,
        adjunct_descs: &[action::Descriptor],
    ) -> Result<BTreeSet<action::Descriptor>, VerifyCoverageError> {
        let own_descs = self.descriptors();

        let n_descs = own_descs.len() + adjunct_descs.len();

        let unique_descs: BTreeSet<action::Descriptor> =
            own_descs.chain(adjunct_descs.iter().copied()).collect();

        if unique_descs.len() != n_descs {
            return Err(VerifyCoverageError::DuplicateActions);
        }

        if !self.stamp.is_covering(unique_descs.clone()) {
            return Err(VerifyCoverageError::StampActionsMismatch);
        }

        Ok(unique_descs)
    }

    /// Verify the stamp's published tachygrams: two per covered action, and
    /// reproducing the carried set commitment. `action_count` is the size of
    /// the covered set returned by [`Self::verify_coverage`].
    ///
    /// # Errors
    ///
    /// Returns [`VerifyTachygramsError`] if the published count is not two
    /// per covered action, or if they do not reproduce the carried set
    /// commitment.
    pub fn verify_tachygrams(
        &self,
        action_count: usize,
    ) -> Result<TachygramSetCommit, VerifyTachygramsError> {
        if self.stamp.tachygrams.len() != 2 * action_count {
            return Err(VerifyTachygramsError::WrongArity);
        }

        let tg_set = TachygramSetPoly::from_iter(self.stamp.tachygrams.iter().copied());

        if self.stamp.tachygram_set != tg_set.commit() {
            return Err(VerifyTachygramsError::WrongSet);
        }

        Ok(self.stamp.tachygram_set)
    }

    /// Verify the pointers of the adjuncts against the expected wtxid,
    /// returning the action descriptors they carry.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyPointersError`] if the wtxid is all-zero or an adjunct
    /// points at a different aggregate.
    pub fn verify_pointers(
        &self,
        wtxid: &[u8; 64],
        adjuncts: &[&Bundle<PointerStamp>],
    ) -> Result<Vec<action::Descriptor>, VerifyPointersError> {
        if let Err(agg_id_err) = PointerStamp::try_from(*wtxid) {
            return Err(VerifyPointersError::AdjunctPointerInvalid(agg_id_err));
        }

        if adjuncts
            .iter()
            .any(|&adj| adj.stamp.stamp_digest() != *wtxid)
        {
            return Err(VerifyPointersError::AdjunctPointerMismatch);
        }

        Ok(adjuncts.iter().flat_map(|&adj| adj.descriptors()).collect())
    }

    /// Verify the stamp's proof against the given action digests.
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
        action_digests: &[ActionDigest],
    ) -> Result<bool, ragu_core::Error> {
        self.stamp.verify_proof(rng, action_digests.iter().copied())
    }

    /// Verify everything about this bundle. Does not verify any details about
    /// the provided adjuncts.
    ///
    /// - Signatures are valid
    /// - Adjuncts are covered
    /// - Tachygrams are consistent
    /// - Proof is correct
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
        sighash: &[u8; 32],
        wtxid: &[u8; 64],
        adjuncts: &[&Bundle<PointerStamp>],
    ) -> Result<(), VerificationError> {
        self.verify_signatures(sighash)
            .map_err(VerificationError::Signatures)?;

        let adjunct_descs = self
            .verify_pointers(wtxid, adjuncts)
            .map_err(VerificationError::Pointers)?;

        let covered_descs = self
            .verify_coverage(&adjunct_descs)
            .map_err(VerificationError::Coverage)?;

        self.verify_tachygrams(covered_descs.len())
            .map_err(VerificationError::Tachygrams)?;

        let covered_digests = covered_descs
            .iter()
            .map(action::Descriptor::digest)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()
            .map_err(VerificationError::Actions)?;

        if self
            .verify_proof(rng, &covered_digests)
            .map_err(VerificationError::Proof)?
        {
            Ok(())
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
    /// action descriptors, action sigs, binding sig, memo, and the stamp
    /// trailer.
    fn read_body<R: Read>(mut reader: R) -> io::Result<Self> {
        let value_balance = {
            let mut bytes = [0u8; size_of::<i64>()];
            reader.read_exact(&mut bytes)?;
            value::Balance::try_from(i64::from_le_bytes(bytes)).map_err(|_err| {
                io::Error::new(io::ErrorKind::InvalidData, "value balance out of range")
            })
        }?;

        // `n_actions` is attacker-controlled up to MAX_COMPACT_SIZE (2^25), so
        // do not pre-allocate vector capacity. vector reads are ASSUMED to hit
        // invalid data or EOF before significant problems occur.
        // TODO: assert a reasonable maximum, to allow pre-allocation?
        let n_actions =
            usize::try_from(serialization::read_compactsize(&mut reader)?).map_err(|_err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "actions vector length exceeds usize",
                )
            })?;

        if n_actions == 0 && value_balance != value::Balance::ZERO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bundle with no actions must have zero value balance",
            ));
        }

        let mut descriptors: Vec<action::Descriptor> = Vec::new();
        for _ in 0..n_actions {
            descriptors.push(action::Descriptor::read(&mut reader)?);
        }

        let mut signatures: Vec<action::Signature> = Vec::new();
        for _ in 0..n_actions {
            signatures.push(action::Signature::read(&mut reader)?);
        }

        let actions: Vec<Action> = descriptors
            .into_iter()
            .zip(signatures)
            .map(Action::from)
            .collect();

        let binding_sig = Signature::read(&mut reader)?;

        // `n_memo` is attacker-controlled up to MAX_COMPACT_SIZE (2^25), so do
        // not pre-allocate, on the same reasoning as `n_actions` above.
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

        let stamp = S::read(&mut reader)?;

        Ok(Self {
            value_balance,
            actions,
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
            action.descriptor().write(&mut writer)?;
        }

        for action in &self.actions {
            action.sig.write(&mut writer)?;
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
    /// Commits the action signatures, the binding signature, and the stamp's
    /// digest. See [`blake2b::bundle_auth_digest`]. The memo is absent here
    /// because it is effecting data, committed by [`Self::commitment`].
    #[must_use]
    pub fn auth_digest(&self) -> [u8; 32] {
        let action_sigs: Vec<[u8; 64]> = self.actions.iter().map(|act| act.sig).collect();
        let binding_sig: [u8; 64] = self.binding_sig.0.into();

        blake2b::bundle_auth_digest(
            S::state_byte().into(),
            &action_sigs,
            &binding_sig,
            &self.stamp.stamp_digest(),
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
    Proven(Bundle<ProofStamp>),
    /// A bundle with no internal proof (adjunct).
    Adjunct(Bundle<PointerStamp>),
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
    /// proof-stamped bundle, and `0x02` as a pointer-stamped bundle;
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
            StateByte::PointerStamped => Self::Adjunct(Bundle::read_body(&mut reader)?),
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

    /// Confirm this bundle has a proof stamp, but its `hStampActionsTachyon`
    /// does not represent this bundle's actions.
    #[must_use]
    pub fn is_aggregate(&self) -> bool {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => false,
            Self::Proven(ref stamped) => stamped.is_aggregate(),
            Self::Adjunct(ref _stamped) => false,
        }
    }

    /// Confirm this bundle has a proof stamp, and its `hStampActionsTachyon`
    /// represents this bundle's actions.
    #[must_use]
    pub fn is_autonome(&self) -> bool {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => false,
            Self::Proven(ref stamped) => stamped.is_autonome(),
            Self::Adjunct(ref _stamped) => false,
        }
    }

    /// Confirm `hStampActionsTachyon` represents the combined actions of this
    /// bundle and the given bundles.
    ///
    /// Descriptors are sorted but not deduplicated, so a collection containing
    /// duplicates mismatches.
    #[must_use]
    pub fn is_covering(&self, adjuncts: &[Self]) -> bool {
        #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
        match *self {
            Self::NoBundle => false,
            Self::Proven(ref stamped) => adjuncts
                .iter()
                .map(|adj| adj.as_dyn())
                .collect::<Option<Vec<&Bundle<dyn StampState>>>>()
                .is_some_and(|dyn_adjuncts| stamped.is_covering(&dyn_adjuncts)),
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
