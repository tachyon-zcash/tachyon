//! Stamps and anchors.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]
#![allow(
    clippy::multiple_inherent_impl,
    clippy::same_name_method,
    reason = "todo: take read/write off StampState"
)]

extern crate alloc;

pub mod proof;

use alloc::{boxed::Box, collections::BTreeSet, format, string::ToString as _, vec, vec::Vec};
use core::error;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, Into, PartialEq};
use proof::{
    HEADER_SIZE, PROOF_SYSTEM, output,
    stamp::{
        ActionLift, ActionMerge, Actions, FeeFuse, FeeSeed, OutputAction, SpendAction, Stamp,
        StampLift, StampMerge, StampUnmerge,
    },
};
use ragu::wire;
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use ragu_core::pasta::Pasta;
use rand_core::CryptoRng;
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use crate::{
    ActionSetPoly, Note, TachygramSetPoly, action,
    bundle::{BundleState, StateByte},
    digest::blake2b,
    effect,
    entropy::ActionEntropy,
    fee,
    keys::{ProofAuthorizingKey, private},
    pasta::{Eq, Fp},
    primitives::{
        ActionDigest, ActionDigestError, ActionSetCommit, Anchor, Tachygram, TachygramSetCommit,
    },
    serialization,
    stamp::proof::{delegation, pool, spend, spendable},
    value, witness,
};

/// Marker for a bundle that has not yet been proven.
///
/// This is the initial state for a newly constructed bundle.
/// Proving produces a [`ProofStamp`].
///
/// `Unproven` has no wire representation: it does not implement
/// [`StampState`], so an unproven bundle cannot be serialized.
///
/// ```compile_fail,E0599
/// use zcash_tachyon::{Bundle, Unproven};
///
/// fn serialize(unproven: &Bundle<Unproven>) {
///     unproven.write(&mut Vec::<u8>::new()); // no `write` on `Bundle<Unproven>`
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Unproven;

/// The 64-byte `wtxid` of the covering aggregate in the same block, assigned by
/// the miner during block assembly.
///
/// Use of the wtxid unambiguously pins the aggregate's specific auth state.
///
/// The all-zero wtxid (which refers to no aggregate) is rejected.
#[derive(Clone, Copy, Debug, Into, PartialEq, TotalEq)]
pub struct AggregateId([u8; 64]);

/// A pointer to the covering aggregate, and the fee of the bundle that
/// carries this stamp.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct PointerStamp {
    /// The covering aggregate's wtxid.
    pub wtxid: AggregateId,

    /// The fee of the bundle that carries this stamp.
    pub fee: value::Positive,
}

#[derive(Clone, Copy, Debug, Display, Error)]
/// Errors that can occur when handling an aggregate id.
pub enum AggregateIdError {
    /// The aggregate id is zero and refers to no aggregate.
    #[display("aggregate id is zero and refers to no aggregate")]
    Zero,
}

impl TryFrom<(&[u8; 32], &[u8; 32])> for AggregateId {
    type Error = AggregateIdError;

    fn try_from((sighash, auth_digest): (&[u8; 32], &[u8; 32])) -> Result<Self, Self::Error> {
        let mut wtxid = [0u8; 64];
        wtxid[..32].copy_from_slice(sighash);
        wtxid[32..].copy_from_slice(auth_digest);
        Self::try_from(wtxid)
    }
}

impl TryFrom<[u8; 64]> for AggregateId {
    type Error = AggregateIdError;

    fn try_from(wtxid: [u8; 64]) -> Result<Self, Self::Error> {
        if wtxid == [0u8; 64] {
            return Err(AggregateIdError::Zero);
        }
        Ok(Self(wtxid))
    }
}

/// Bundle states that carry a stamp: [`ProofStamp`] or [`PointerStamp`].
/// The intermediate [`Unproven`] state has no stamp.
pub trait StampState: BundleState {
    /// A stamp's 72-byte `tachyonStampState`.
    ///
    /// For a [`ProofStamp`], this is
    /// `LE64(vFeeTachyon) || hStampCoverageTachyon || hStampDataTachyon`.
    /// For a [`PointerStamp`], this is `LE64(vFeeTachyon) ||
    /// tachyonAggregateId`.
    fn stamp_digest(&self) -> [u8; 72];

    /// The fee of the bundle that carries this stamp.
    fn fee(&self) -> value::Positive;

    /// The `tachyonBundleState` wire byte for this state.
    fn state_byte() -> StateByte
    where
        Self: Sized;

    /// Read the stamp trailer from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or the trailer is not a canonical
    /// encoding of this state.
    fn read<R: Read>(reader: &mut R) -> io::Result<Self>
    where
        Self: Sized;

    /// Write the stamp trailer in the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()>
    where
        Self: Sized;
}

impl StampState for PointerStamp {
    fn stamp_digest(&self) -> [u8; 72] {
        let mut stamp_digest = [0u8; 72];
        stamp_digest[..8].copy_from_slice(&u64::from(self.fee).to_le_bytes());
        stamp_digest[8..].copy_from_slice(&self.wtxid.0);

        stamp_digest
    }

    fn fee(&self) -> value::Positive {
        self.fee
    }

    fn state_byte() -> StateByte {
        StateByte::PointerStamped
    }

    fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        Self::read(reader)
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write(writer)
    }
}

impl PointerStamp {
    /// Read a fee and an aggregate id from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails, the fee exceeds `MAX_MONEY`, or the
    /// wtxid is all-zero, which refers to no aggregate.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let fee = {
            let mut bytes = [0u8; size_of::<u64>()];
            reader.read_exact(&mut bytes)?;
            value::Positive::try_from(u64::from_le_bytes(bytes))
                .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "fee out of range"))
        }?;

        let mut wtxid = [0u8; 64];
        reader.read_exact(&mut wtxid)?;
        let aggregate = AggregateId::try_from(wtxid).map_err(|_err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "aggregate id is zero and refers to no aggregate",
            )
        })?;
        Ok(Self {
            wtxid: aggregate,
            fee,
        })
    }

    /// Write a fee and an aggregate id to the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails or the wtxid is all-zero, which
    /// refers to no aggregate.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.wtxid.0 == [0u8; 64] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "aggregate id is zero and refers to no aggregate",
            ));
        }
        writer.write_all(&u64::from(self.fee).to_le_bytes())?;
        writer.write_all(&self.wtxid.0)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Uncompressed {}
    impl Sealed for super::Compressed {}
}

/// The Ragu proof a [`ProofStamp`] carries: [`Uncompressed`] or [`Compressed`].
pub trait Proof: sealed::Sealed {
    /// The proof-encoding transport bound for this application.
    fn encoded_len() -> usize;

    /// The proof's Ragu encoding.
    ///
    /// # Errors
    ///
    /// Returns [`wire::Error`] if the proof has no encoding.
    fn to_bytes(&self) -> Result<Vec<u8>, wire::Error<'static>>;

    /// Decode a proof from its Ragu encoding.
    ///
    /// # Errors
    ///
    /// Returns [`wire::Error`] if the bytes do not encode this proof type.
    fn from_bytes(bytes: &[u8]) -> Result<Self, wire::Error<'_>>
    where
        Self: Sized;

    /// Verify both output sets and the stamp's anchor.
    ///
    /// # Errors
    ///
    /// Returns [`ragu_core::Error`] if the proof system fails. A disproved
    /// proof is reported as `Ok(false)`, not an error.
    fn verify<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        header: (ActionSetCommit, TachygramSetCommit, Anchor),
    ) -> Result<bool, ragu_core::Error>;
}

impl Proof for Uncompressed {
    fn encoded_len() -> usize {
        Self::encoded_len::<HEADER_SIZE>()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, wire::Error<'static>> {
        self.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, wire::Error<'_>> {
        Self::from_bytes(bytes)
    }

    fn verify<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        header: (ActionSetCommit, TachygramSetCommit, Anchor),
    ) -> Result<bool, ragu_core::Error> {
        let pcd = self.clone().carry::<Stamp>((header.1.bridge()?, header.2));
        let [action_slot, tachygram_slot] = pcd.commitments();
        if action_slot != Eq::from(header.0).to_affine()
            || tachygram_slot != Eq::from(header.1).to_affine()
        {
            return Ok(false);
        }
        let compressed = match PROOF_SYSTEM.compress(&pcd, rng) {
            Ok(compressed) => compressed,
            Err(ragu_core::Error::InvalidWitness(_)) => return Ok(false),
            Err(error) => return Err(error),
        };
        PROOF_SYSTEM.verify_compressed(&compressed)
    }
}

impl Proof for Compressed {
    fn encoded_len() -> usize {
        Self::encoded_len::<ProductionRank, HEADER_SIZE>()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, wire::Error<'static>> {
        self.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, wire::Error<'_>> {
        Self::from_bytes(bytes)
    }

    fn verify<RNG: CryptoRng>(
        &self,
        _rng: &mut RNG,
        header: (ActionSetCommit, TachygramSetCommit, Anchor),
    ) -> Result<bool, ragu_core::Error> {
        let [action_slot, tachygram_slot] = self.online_commitments();
        if action_slot != Eq::from(header.0).to_affine()
            || tachygram_slot != Eq::from(header.1).to_affine()
        {
            return Ok(false);
        }
        PROOF_SYSTEM.verify_compressed(&self.clone().carry::<Stamp>((header.1.bridge()?, header.2)))
    }
}

impl<P: Proof> StampState for ProofStamp<P> {
    fn stamp_digest(&self) -> [u8; 72] {
        let stamp_data_digest: [u8; 32] = {
            #[expect(
                clippy::expect_used,
                reason = "a proved or decoded stamp proof is encodable"
            )]
            let proof = self.proof.to_bytes().expect("stamp proof is encodable");
            let anchor: [u8; 32] = self.anchor.0.to_bytes();

            // Do NOT sort here: a constructed stamp should already be canonical.
            let tachygrams: Vec<[u8; 32]> = self
                .tachygrams
                .iter()
                .map(|&tg| Fp::from(tg).to_bytes())
                .collect();

            blake2b::stamp_data_digest(
                blake2b::stamp_proof_digest(proof.as_ref()),
                anchor,
                self.tachygram_set.as_ref().to_affine().to_bytes(),
                &tachygrams,
            )
        };

        let mut stamp_digest = [0u8; 72];
        stamp_digest[..8].copy_from_slice(&u64::from(self.fee).to_le_bytes());
        stamp_digest[8..40].copy_from_slice(&self.coverage);
        stamp_digest[40..].copy_from_slice(&stamp_data_digest);

        stamp_digest
    }

    fn fee(&self) -> value::Positive {
        self.fee
    }

    fn state_byte() -> StateByte {
        StateByte::ProofStamped
    }

    fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        Self::read(reader)
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write(writer)
    }
}

impl<P: Proof> ProofStamp<P> {
    /// Read a stamp from the consensus wire format. The proof blob has a
    /// compactSize prefix and is bounded by the proof type's encoded length.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or any component is not a canonical
    /// encoding.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let fee = {
            let mut bytes = [0u8; size_of::<u64>()];
            reader.read_exact(&mut bytes)?;
            value::Positive::try_from(u64::from_le_bytes(bytes))
                .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "fee out of range"))
        }?;

        let mut covered_actions = [0u8; 32];
        reader.read_exact(&mut covered_actions)?;

        let anchor = Anchor::read(&mut reader)?;

        // Parsing does not confirm this against the tachygrams below.
        let tachygram_set =
            TachygramSetCommit::from(Eq::from(serialization::read_eq_affine(&mut reader)?));

        // `n_tachygrams` is attacker-controlled up to MAX_COMPACT_SIZE (2^25)
        let n_tachygrams = usize::try_from(serialization::read_compactsize(&mut reader)?)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        // proof stamp should never have an empty set
        if n_tachygrams == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no tachygrams"));
        }

        // the polynomial multiset includes a constant term
        if (n_tachygrams + 1) > ProductionRank::num_coeffs() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many tachygrams",
            ));
        }

        let mut tachygrams: BTreeSet<Tachygram> = BTreeSet::new();
        for _ in 0..n_tachygrams {
            let tg = Tachygram::from(serialization::read_fp(&mut reader)?);

            if !tachygrams.insert(tg) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tachygrams are not unique",
                ));
            }

            if tachygrams.last() != Some(&tg) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tachygrams are not canonically sorted",
                ));
            }
        }

        let proof = {
            let proof_len = usize::try_from(serialization::read_compactsize(&mut reader)?)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            if proof_len > P::encoded_len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proof size exceeds transport bound",
                ));
            }
            let mut bytes = vec![0u8; proof_len];
            reader.read_exact(&mut bytes)?;
            P::from_bytes(&bytes)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?
        };

        Ok(Self {
            coverage: covered_actions,
            anchor,
            tachygram_set,
            tachygrams,
            proof: Box::new(proof),
            fee,
        })
    }

    /// Write a stamp to the consensus wire format. The proof blob has a
    /// compactSize prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails or the proof has no encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&u64::from(self.fee).to_le_bytes())?;
        writer.write_all(&self.coverage)?;
        self.anchor.write(&mut writer)?;
        serialization::write_eq_affine(&mut writer, &self.tachygram_set.as_ref().to_affine())?;
        serialization::write_compactsize(
            &mut writer,
            u64::try_from(self.tachygrams.len()).map_err(|_err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tachygram vector length exceeds u64",
                )
            })?,
        )?;
        for &tg in &self.tachygrams {
            serialization::write_fp(&mut writer, &Fp::from(tg))?;
        }
        let proof = self
            .proof
            .to_bytes()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        serialization::write_compactsize(
            &mut writer,
            u64::try_from(proof.len()).map_err(|_err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proof encoding length exceeds u64",
                )
            })?,
        )?;
        writer.write_all(&proof)
    }
}

/// Everything needed to produce a [`ProofStamp`].
///
/// The statement is each action's descriptor `(cv, rk)`, the fee descriptor,
/// and the `anchor`. The planned witnesses are each action's `theta` and
/// `rcv`, each output's `note`, and the max fee note with the `fee` it pays
/// and the derived fee change note. A spend's note comes from its
/// [`delegation::NoteSecret`] PCD at [`Self::prove`].
///
/// Construct via [`Plan::new`] or via
/// [`Plan::stamp_plan`](crate::bundle::Plan::stamp_plan) for the typed
/// single-party path.
#[derive(Clone, Debug)]
pub struct Plan {
    spends: Vec<(action::Descriptor, ActionEntropy, value::Trapdoor)>,
    outputs: Vec<(action::Descriptor, ActionEntropy, Note, value::Trapdoor)>,
    anchor: Anchor,
    max_fee_note: Note,
    fee: value::Positive,
    fee_change_note: Note,
}

impl Plan {
    /// Create a stamp plan from paired action descriptors and witnesses, the
    /// max fee note and the fee. Derives and stores the fee change note.
    ///
    /// # Panics
    ///
    /// Panics if the fee exceeds the max fee note's value.
    #[must_use]
    pub fn new(
        spends: Vec<(action::Descriptor, ActionEntropy, value::Trapdoor)>,
        outputs: Vec<(action::Descriptor, ActionEntropy, Note, value::Trapdoor)>,
        anchor: Anchor,
        max_fee_note: Note,
        fee: value::Positive,
    ) -> Self {
        #[expect(clippy::expect_used, reason = "the fee must not exceed the maximum")]
        let fee_change_note = Note {
            value: value::Positive::try_from(i128::from(max_fee_note.value) - i128::from(fee))
                .expect("fee should not exceed max fee"),
            ..max_fee_note
        };
        Self {
            spends,
            outputs,
            anchor,
            max_fee_note,
            fee,
            fee_change_note,
        }
    }

    /// Prove a single [`ProofStamp`] for this plan.
    ///
    /// `spend_pcds` pairs with the planned spends by position. For each
    /// **spend**, [`spend::SpendBind`] derives the live nullifier pair and
    /// [`ProofStamp::prove_spend`] proves the action at the spendable's
    /// anchor. If that anchor differs from the plan's anchor, the spend comes
    /// with a list of [`AnchorSpan`](pool::AnchorSpan)s and their members
    /// polynomials. [`ActionLift`] moves the spend's actions along each span in
    /// order. The first span must contain the spendable's anchor, each later
    /// span must contain the previous span's `anchor_end`, and the last span
    /// must end at the plan's anchor. For each **output**,
    /// [`ProofStamp::prove_output`] proves the action at the plan's anchor.
    ///
    /// The planned actions are recursively merged via [`ActionMerge`] into a
    /// single proof, whose coverage is the planned descriptors. [`FeeFuse`]
    /// then applies the fee, or [`FeeSeed`] proves it for a plan with no
    /// actions.
    ///
    /// # Errors
    ///
    /// - [`ProveError::MissingPcd`] if the spend PCDs do not match the planned
    ///   spends, or a spend does not reach the plan's anchor.
    /// - [`ProveError::ActionDigest`] if a proved action has no digest.
    /// - [`ProveError::ProofFailed`] if a proof-system step fails.
    ///
    /// # Panics
    ///
    /// Panics if the max fee note's `rcm` is zero, or if the plan has no
    /// actions and the max fee note's value is nonzero.
    #[expect(
        clippy::type_complexity,
        reason = "each spend's secret, spendable and anchor spans"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "proves, lifts and merges every planned action"
    )]
    pub fn prove<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        pak: &ProofAuthorizingKey,
        spend_pcds: Vec<(
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
        )>,
    ) -> Result<ProofStamp<Uncompressed>, ProveError> {
        let fee_descriptor = fee::Descriptor {
            cv_feemax: self.max_fee_note.cv_feemax(),
            v_fee: self.fee,
        };
        let change = Tachygram::from(self.fee_change_note.commitment());

        // Each entry pairs leaf stamp components with the descriptor of its
        // covered action; merges concatenate both. The covered-actions digest
        // is computed once, on the final stamp.
        let mut entries = Vec::with_capacity(self.spends.len() + self.outputs.len());

        if self.spends.len() != spend_pcds.len() {
            return Err(ProveError::MissingPcd(
                format!(
                    "cannot prove {} spend actions with {} spendbind inputs",
                    self.spends.len(),
                    spend_pcds.len(),
                )
                .into(),
            ));
        }

        for (index, ((desc, theta, rcv), (secret_pcd, spendable_pcd, spans))) in
            self.spends.into_iter().zip(spend_pcds).enumerate()
        {
            let reached = spans
                .last()
                .map_or_else(|| spendable_pcd.data().2, |last| last.data().1);
            if reached != self.anchor {
                return Err(ProveError::MissingPcd(
                    format!("spend {index} does not reach the plan's anchor").into(),
                ));
            }

            // SpendBind: derive the live pair from the note's master key and
            // commit the note's value.
            let (bind_pcd, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    spend::SpendBind,
                    witness::spend_bind((*spendable_pcd.data(), *secret_pcd.data()), rcv),
                    spendable_pcd,
                    secret_pcd,
                )
                .map_err(ProveError::ProofFailed)?;

            let (digests, tachygrams, spend_anchor, spend_proof) =
                ProofStamp::prove_spend(rng, theta, bind_pcd, *pak)?;
            let mut stamp_pcd = spend_proof.carry::<Actions>(spend_anchor);
            for span in spans {
                stamp_pcd = PROOF_SYSTEM
                    .fuse(rng, ActionLift, (), stamp_pcd, span)
                    .map_err(ProveError::ProofFailed)?
                    .0;
            }

            let (proof, anchor) = stamp_pcd.into_parts();
            entries.push((
                BTreeSet::from_iter([desc]),
                digests,
                tachygrams,
                anchor,
                Box::new(proof),
            ));
        }

        for (desc, theta, note, rcv) in self.outputs {
            let (digests, tachygrams, anchor, proof) =
                ProofStamp::prove_output(rng, theta, rcv, note, self.anchor)?;
            entries.push((
                BTreeSet::from_iter([desc]),
                digests,
                tachygrams,
                anchor,
                proof,
            ));
        }

        let (pcd, descriptors, mut tachygrams) = match entries
            .into_iter()
            .map(Ok)
            .reduce(|acc, next| {
                let (left_desc, left_digests, left_tachygrams, left_anchor, left_proof) = acc?;
                let (right_desc, right_digests, right_tachygrams, right_anchor, right_proof) =
                    next?;

                let left_pcd = left_proof.carry::<Actions>(left_anchor);
                let right_pcd = right_proof.carry::<Actions>(right_anchor);

                let merged_digests: BTreeSet<ActionDigest> =
                    left_digests.union(&right_digests).copied().collect();
                let merged_tachygrams: BTreeSet<Tachygram> =
                    left_tachygrams.union(&right_tachygrams).copied().collect();

                let (pcd, ()) = PROOF_SYSTEM
                    .fuse(
                        rng,
                        ActionMerge,
                        witness::action_merge(
                            (*left_pcd.data(), *right_pcd.data()),
                            ActionSetPoly::from_iter(merged_digests.clone()),
                            TachygramSetPoly::from_iter(merged_tachygrams.clone()),
                        ),
                        left_pcd,
                        right_pcd,
                    )
                    .map_err(ProveError::ProofFailed)?;

                let merged_descs = left_desc.union(&right_desc).copied().collect();

                Ok((
                    merged_descs,
                    merged_digests,
                    merged_tachygrams,
                    *pcd.data(),
                    Box::new(pcd.proof().clone()),
                ))
            })
            .transpose()?
        {
            None => {
                let (pcd, ()) = PROOF_SYSTEM
                    .seed(
                        rng,
                        FeeSeed,
                        witness::fee_seed(((), ()), self.max_fee_note, self.anchor),
                    )
                    .map_err(ProveError::ProofFailed)?;
                (pcd, BTreeSet::new(), BTreeSet::new())
            },
            Some((descriptors, digests, tachygrams, anchor, merged_proof)) => {
                let (pcd, ()) = PROOF_SYSTEM
                    .fuse(
                        rng,
                        FeeFuse,
                        witness::fee_fuse(
                            (anchor, ()),
                            self.max_fee_note,
                            self.fee,
                            &digests,
                            &tachygrams,
                        ),
                        merged_proof.carry::<Actions>(anchor),
                        PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
                    )
                    .map_err(ProveError::ProofFailed)?;
                (pcd, descriptors, tachygrams)
            },
        };

        let (proof, (_, anchor)) = PROOF_SYSTEM
            .rerandomize(pcd, rng)
            .map_err(ProveError::ProofFailed)?
            .into_parts();
        tachygrams.insert(change);
        let tachygram_set = tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();
        Ok(ProofStamp {
            coverage: blake2b::stamp_coverage_digest(
                &blake2b::action_descriptor_digest(&Vec::<[u8; 64]>::from_iter(descriptors)),
                &blake2b::stamp_fees_digest(&[fee_descriptor.into()]),
            ),
            anchor,
            tachygram_set,
            tachygrams,
            proof: Box::new(proof),
            fee: self.fee,
        })
    }
}

/// Errors that can occur while proving a stamp.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ProveError {
    /// Missing PCD inputs for the operation.
    #[display("missing pcd inputs: {_0}")]
    MissingPcd(Box<dyn error::Error + Send + Sync + 'static>),
    /// Action digest construction failed (cv or rk was the identity point).
    #[display("action digest failed: {_0}")]
    ActionDigest(ActionDigestError),
    /// Proof creation failed; carries the underlying step-level error.
    #[display("proof failed: {_0}")]
    ProofFailed(ragu_core::Error),
}

/// An uncompressed Ragu proof.
pub type Uncompressed = ragu::Proof<Pasta, ProductionRank>;

/// A compressed Ragu proof.
pub type Compressed = ragu::CompressedProof<Pasta>;

/// A stamp carrying tachygrams, anchor, and a proof for specific actions.
///
/// The PCD header `(tachygram_bridge, anchor)` is entirely not stored
/// here.  The covered actions are present only as reference. A verifier must
/// reconstruct the header from public data and check the proof's output slots
/// against the covered actions and [`Self::tachygram_set`].
///
/// Only the uncompressed proof type supports lifting, merging and
/// unmerging. Compressed stamps support reading, writing and verification.
#[derive(Clone, Debug)]
pub struct ProofStamp<P: Proof> {
    /// The digest $\mathsf{hStampCoverageTachyon}$ of the proof's covered
    /// action descriptors and fee descriptors from this stamp's bundle and
    /// all covered bundles.
    ///
    /// See [`blake2b::stamp_coverage_digest`]
    pub coverage: [u8; 32],

    /// The historic pool state for which this stamp is valid.
    pub anchor: Anchor,

    /// The commitment to this stamp's tachygram set, which may not be
    /// consistent with [`Self::tachygrams`].
    pub tachygram_set: TachygramSetCommit,

    /// The contents of this stamp's tachygram set, which may not be consistent
    /// with [`Self::tachygram_set`].
    pub tachygrams: BTreeSet<Tachygram>,

    /// The full or compressed Ragu proof.
    #[debug(skip)]
    pub proof: Box<P>,

    /// The fee of the bundle that carries this stamp.
    pub fee: value::Positive,
}

impl ProofStamp<Uncompressed> {
    /// Proves a single output action, returning `(digests, tachygrams,
    /// anchor, proof)`. The proof is not rerandomized.
    ///
    /// [`output::OutputBind`] settles the tachygram pair, then [`OutputAction`]
    /// derives `alpha` from `theta` and the bound `cm`, proves the action over
    /// the pair, and enforces the stamp accumulator. Both tachygrams
    /// are derived inside the circuit and placed on the stamp for data
    /// availability. `digests` holds the proved action's digest.
    ///
    /// # Errors
    ///
    /// - [`ProveError::ActionDigest`] if the proved action has no digest.
    /// - [`ProveError::ProofFailed`] if a proof-system step fails.
    #[expect(
        clippy::type_complexity,
        reason = "the digests, tachygrams, anchor and proof of one stamp"
    )]
    fn prove_output<RNG: CryptoRng>(
        rng: &mut RNG,
        theta: ActionEntropy,
        rcv: value::Trapdoor,
        note: Note,
        anchor: Anchor,
    ) -> Result<
        (
            BTreeSet<ActionDigest>,
            BTreeSet<Tachygram>,
            Anchor,
            Box<Uncompressed>,
        ),
        ProveError,
    > {
        let alpha = theta.randomizer::<effect::Output>(note.commitment());
        let digest = ActionDigest::new(
            rcv.commit(-note.value),
            private::ActionSigningKey::new(&alpha).derive_action_public(),
        )
        .map_err(ProveError::ActionDigest)?;

        let (bind_pcd, ()) = PROOF_SYSTEM
            .seed(
                rng,
                output::OutputBind,
                witness::output_bind(((), ()), note, rcv),
            )
            .map_err(ProveError::ProofFailed)?;
        let (cm, pad, _cv) = *bind_pcd.data();
        let tachygrams = BTreeSet::from_iter([cm, pad]);

        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                OutputAction,
                witness::output_action((*bind_pcd.data(), ()), theta, anchor),
                bind_pcd,
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .map_err(ProveError::ProofFailed)?;

        Ok((
            BTreeSet::from_iter([digest]),
            tachygrams,
            anchor,
            Box::new(pcd.proof().clone()),
        ))
    }

    /// Proves a single spend action from a bound
    /// [`SpendHeader`](spend::SpendHeader) PCD, returning `(digests,
    /// tachygrams, anchor, proof)`. The proof is not rerandomized.
    ///
    /// The nullifier pair `{nf_current, nf_next}` published for data
    /// availability and the value commitment `cv` are read straight off the
    /// bind header (both derived at [`SpendBind`](spend::SpendBind)).
    /// [`SpendAction`] derives `alpha` from `theta` and the bound `cm`, proves
    /// the action `(cv, rk)`, and enforces the stamp accumulator over the
    /// pair. The spend's `anchor` is taken as the stamp's anchor; chain
    /// validation lives inside the spendable lineage. `digests` holds the
    /// proved action's digest.
    ///
    /// # Errors
    ///
    /// - [`ProveError::ActionDigest`] if the proved action has no digest.
    /// - [`ProveError::ProofFailed`] if a proof-system step fails.
    #[expect(
        clippy::type_complexity,
        reason = "the digests, tachygrams, anchor and proof of one stamp"
    )]
    fn prove_spend<RNG: CryptoRng>(
        rng: &mut RNG,
        theta: ActionEntropy,
        bind_pcd: ragu::Pcd<Pasta, ProductionRank, spend::SpendHeader>,
        pak: ProofAuthorizingKey,
    ) -> Result<
        (
            BTreeSet<ActionDigest>,
            BTreeSet<Tachygram>,
            Anchor,
            Box<Uncompressed>,
        ),
        ProveError,
    > {
        let (cm, nf_current, nf_next, anchor, _pk, cv) = *bind_pcd.data();
        let alpha = theta.randomizer::<effect::Spend>(cm);
        let digest = ActionDigest::new(cv, pak.ak.derive_action_public(&alpha))
            .map_err(ProveError::ActionDigest)?;

        let tachygrams =
            BTreeSet::from_iter([Tachygram::from(nf_current), Tachygram::from(nf_next)]);

        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                SpendAction,
                witness::spend_action((*bind_pcd.data(), ()), theta, pak),
                bind_pcd,
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .map_err(ProveError::ProofFailed)?;

        Ok((
            BTreeSet::from_iter([digest]),
            tachygrams,
            anchor,
            Box::new(pcd.proof().clone()),
        ))
    }

    /// Proves the merge of two stamps, returning the merged `(digests,
    /// tachygrams, anchor, proof)`. The proof is not rerandomized.
    ///
    /// Both stamps must share the same anchor (use [`StampLift`] to align
    /// first).
    ///
    /// Each side is `(digests, tachygrams, anchor, proof)`, where the digest
    /// list reconstructs the `ActionCommit` multiset that `StampMerge`
    /// verifies via Schwartz-Zippel. Digests are derived from public action
    /// data by the caller and are never stored on the stamp; the merged
    /// (concatenated) digest list is returned so a fold can carry it
    /// forward without re-deriving.
    ///
    /// # Errors
    ///
    /// Returns [`ragu_core::Error`] if a proof-system step fails.
    #[expect(
        clippy::type_complexity,
        reason = "the digests, tachygrams, anchor and proof of each stamp"
    )]
    fn prove_merge<RNG: CryptoRng>(
        rng: &mut RNG,
        (left_digests, left_tachygrams, left_anchor, left_proof): (
            BTreeSet<ActionDigest>,
            BTreeSet<Tachygram>,
            Anchor,
            Box<Uncompressed>,
        ),
        (right_digests, right_tachygrams, right_anchor, right_proof): (
            BTreeSet<ActionDigest>,
            BTreeSet<Tachygram>,
            Anchor,
            Box<Uncompressed>,
        ),
    ) -> Result<
        (
            BTreeSet<ActionDigest>,
            BTreeSet<Tachygram>,
            Anchor,
            Box<Uncompressed>,
        ),
        ragu_core::Error,
    > {
        let left_tg_poly = left_tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>();

        let right_tg_poly = right_tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>();

        let left_pcd = left_proof.carry::<Stamp>((left_tg_poly.commit().bridge()?, left_anchor));
        let right_pcd =
            right_proof.carry::<Stamp>((right_tg_poly.commit().bridge()?, right_anchor));

        let merged_digests: BTreeSet<ActionDigest> =
            left_digests.union(&right_digests).copied().collect();
        let tachygrams: BTreeSet<Tachygram> =
            left_tachygrams.union(&right_tachygrams).copied().collect();

        let (pcd, ()) = PROOF_SYSTEM.fuse(
            rng,
            StampMerge,
            witness::stamp_merge(
                (*left_pcd.data(), *right_pcd.data()),
                ActionSetPoly::from_iter(merged_digests.clone()),
                TachygramSetPoly::from_iter(tachygrams.clone()),
            ),
            left_pcd,
            right_pcd,
        )?;

        Ok((
            merged_digests,
            tachygrams,
            pcd.data().1,
            Box::new(pcd.proof().clone()),
        ))
    }

    /// Advances the stamp's anchor along `spans`. The first span must contain
    /// the stamp's anchor, and each later span must contain the previous span's
    /// `anchor_end`.
    ///
    /// # Errors
    ///
    /// - [`ProveError::MissingPcd`] if no span is provided.
    /// - [`ProveError::ProofFailed`] if a proof-system step fails, including
    ///   when `action_digests` are not the stamp's action set.
    fn prove_lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        action_digests: impl IntoIterator<Item = ActionDigest>,
        spans: Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Result<Self, ProveError> {
        if spans.is_empty() {
            return Err(ProveError::MissingPcd(
                "no anchor span proof for no anchor advance".into(),
            ));
        }

        let action_set = action_digests.into_iter().collect::<ActionSetPoly>();
        let mut stamp_pcd = self.proof.carry::<Stamp>((
            self.tachygram_set
                .bridge()
                .map_err(ProveError::ProofFailed)?,
            self.anchor,
        ));
        for span in spans {
            stamp_pcd = PROOF_SYSTEM
                .fuse(
                    rng,
                    StampLift,
                    witness::stamp_lift((*stamp_pcd.data(), *span.data()), action_set.clone()),
                    stamp_pcd,
                    span,
                )
                .map_err(ProveError::ProofFailed)?
                .0;
        }
        let anchor = stamp_pcd.data().1;
        let proof = PROOF_SYSTEM
            .rerandomize(stamp_pcd, rng)
            .map_err(ProveError::ProofFailed)?
            .proof()
            .clone();

        Ok(Self {
            coverage: self.coverage,
            anchor,
            tachygram_set: self.tachygram_set,
            tachygrams: self.tachygrams,
            proof: Box::new(proof),
            fee: self.fee,
        })
    }

    /// Advances the stamp's anchor along `spans`, computing the action digests
    /// from the covered descriptors. The lifted stamp keeps this stamp's fee.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError`] if an action digest cannot be computed, no span
    /// is provided, or a proof-system step fails. `StampLift` fails when the
    /// descriptors are not the stamp's covered actions.
    pub fn lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        descriptors: &BTreeSet<action::Descriptor>,
        fee_descriptors: &BTreeSet<fee::Descriptor>,
        spans: Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Result<Self, ProveError> {
        let action_digests = descriptors
            .iter()
            .map(action::Descriptor::digest)
            .chain(fee_descriptors.iter().map(fee::Descriptor::digest))
            .collect::<Result<BTreeSet<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;

        self.prove_lift(rng, action_digests, spans)
    }

    /// Merges two stamps into one covering stamp.
    ///
    /// Each side pairs a stamp with its covered action and fee descriptors.
    /// The action digests for the merge proof and the merged
    /// `covered_actions` are both derived from the descriptor lists.
    ///
    /// The merged stamp stays with this stamp's bundle and keeps this stamp's
    /// fee, and the other stamp's bundle is stripped.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError`] if an action digest cannot be computed or a
    /// proof-system step fails.
    pub fn merge<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        (left_desc, left_fees): (BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>),
        (right_stamp, right_desc, right_fees): (
            Self,
            BTreeSet<action::Descriptor>,
            BTreeSet<fee::Descriptor>,
        ),
    ) -> Result<Self, ProveError> {
        let left_actions_digest = left_desc
            .iter()
            .map(action::Descriptor::digest)
            .chain(left_fees.iter().map(fee::Descriptor::digest))
            .collect::<Result<BTreeSet<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;
        let right_actions_digest = right_desc
            .iter()
            .map(action::Descriptor::digest)
            .chain(right_fees.iter().map(fee::Descriptor::digest))
            .collect::<Result<BTreeSet<ActionDigest>, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;

        let (_, tachygrams, anchor, merged_proof) = Self::prove_merge(
            rng,
            (
                left_actions_digest,
                self.tachygrams,
                self.anchor,
                self.proof,
            ),
            (
                right_actions_digest,
                right_stamp.tachygrams,
                right_stamp.anchor,
                right_stamp.proof,
            ),
        )
        .map_err(ProveError::ProofFailed)?;

        let coverage = blake2b::stamp_coverage_digest(
            &blake2b::action_descriptor_digest(
                &left_desc
                    .union(&right_desc)
                    .copied()
                    .collect::<Vec<[u8; 64]>>(),
            ),
            &blake2b::stamp_fees_digest(
                &left_fees
                    .union(&right_fees)
                    .copied()
                    .map(<[u8; 40]>::from)
                    .collect::<Vec<[u8; 40]>>(),
            ),
        );

        let tachygram_set = tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();
        let proof = PROOF_SYSTEM
            .rerandomize(
                merged_proof.carry::<Stamp>((
                    tachygram_set.bridge().map_err(ProveError::ProofFailed)?,
                    anchor,
                )),
                rng,
            )
            .map_err(ProveError::ProofFailed)?
            .proof()
            .clone();

        Ok(Self {
            coverage,
            anchor,
            tachygram_set,
            tachygrams,
            proof: Box::new(proof),
            fee: self.fee,
        })
    }

    /// Divides this stamp by a divisor stamp at the same anchor, removing the
    /// divisor's covered actions, fees and tachygrams.
    ///
    /// Each side pairs a stamp with its covered action and fee descriptors.
    /// The quotient stays with this stamp's bundle and keeps this stamp's fee,
    /// undoing a merge of the divisor into this stamp. A divisor that removes
    /// this stamp's bundle leaves a quotient whose fee belongs to a bundle it
    /// no longer covers, and merging it into another stamp keeps that stamp's
    /// fee. A divisor that does not divide this stamp fails in the proof
    /// system.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError`] if an action digest cannot be computed or a
    /// proof-system step fails.
    pub fn unmerge<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        (desc, fees): (BTreeSet<action::Descriptor>, BTreeSet<fee::Descriptor>),
        (divisor_stamp, divisor_desc, divisor_fees): (
            Self,
            BTreeSet<action::Descriptor>,
            BTreeSet<fee::Descriptor>,
        ),
    ) -> Result<Self, ProveError> {
        let quotient_desc: BTreeSet<action::Descriptor> =
            desc.difference(&divisor_desc).copied().collect();
        let quotient_fees: BTreeSet<fee::Descriptor> =
            fees.difference(&divisor_fees).copied().collect();
        let tachygrams: BTreeSet<Tachygram> = self
            .tachygrams
            .difference(&divisor_stamp.tachygrams)
            .copied()
            .collect();

        let quotient_action_set = quotient_desc
            .iter()
            .map(action::Descriptor::digest)
            .chain(quotient_fees.iter().map(fee::Descriptor::digest))
            .collect::<Result<ActionSetPoly, ActionDigestError>>()
            .map_err(ProveError::ActionDigest)?;

        let dividend_tachygram_set = self
            .tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>();
        let quotient_tachygram_set = tachygrams.iter().copied().collect::<TachygramSetPoly>();
        let tachygram_set = quotient_tachygram_set.commit();
        let divisor_tachygram_set = divisor_stamp
            .tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>();

        let dividend_pcd = self.proof.carry::<Stamp>((
            dividend_tachygram_set
                .commit()
                .bridge()
                .map_err(ProveError::ProofFailed)?,
            self.anchor,
        ));
        let divisor_pcd = divisor_stamp.proof.carry::<Stamp>((
            divisor_tachygram_set
                .commit()
                .bridge()
                .map_err(ProveError::ProofFailed)?,
            divisor_stamp.anchor,
        ));

        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                StampUnmerge,
                witness::stamp_unmerge(
                    (*dividend_pcd.data(), *divisor_pcd.data()),
                    quotient_action_set,
                    quotient_tachygram_set,
                ),
                dividend_pcd,
                divisor_pcd,
            )
            .map_err(ProveError::ProofFailed)?;

        let coverage = blake2b::stamp_coverage_digest(
            &blake2b::action_descriptor_digest(
                &quotient_desc.into_iter().collect::<Vec<[u8; 64]>>(),
            ),
            &blake2b::stamp_fees_digest(
                &quotient_fees
                    .into_iter()
                    .map(<[u8; 40]>::from)
                    .collect::<Vec<[u8; 40]>>(),
            ),
        );

        let anchor = pcd.data().1;
        let proof = PROOF_SYSTEM
            .rerandomize(pcd, rng)
            .map_err(ProveError::ProofFailed)?
            .proof()
            .clone();

        Ok(Self {
            coverage,
            anchor,
            tachygram_set,
            tachygrams,
            proof: Box::new(proof),
            fee: self.fee,
        })
    }

    /// Compresses the stamp's proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError::ProofFailed`] if the proof system fails.
    pub fn compress<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
    ) -> Result<ProofStamp<Compressed>, ProveError> {
        let pcd = self.proof.carry::<Stamp>((
            self.tachygram_set
                .bridge()
                .map_err(ProveError::ProofFailed)?,
            self.anchor,
        ));
        let (compressed, _) = PROOF_SYSTEM
            .compress(&pcd, rng)
            .map_err(ProveError::ProofFailed)?
            .into_parts();
        Ok(ProofStamp {
            coverage: self.coverage,
            anchor: self.anchor,
            tachygram_set: self.tachygram_set,
            tachygrams: self.tachygrams,
            proof: Box::new(compressed),
            fee: self.fee,
        })
    }
}

impl<P: Proof> ProofStamp<P> {
    /// Confirm `hStampCoverageTachyon` represents the given descriptors.
    ///
    /// # Soundness
    ///
    /// The parameters are multisets: order does not matter, multiplicity does.
    #[must_use]
    pub fn is_covering(
        &self,
        action_descs: impl IntoIterator<Item = action::Descriptor>,
        fee_descriptors: impl IntoIterator<Item = fee::Descriptor>,
    ) -> bool {
        let mut desc_bytes = action_descs.into_iter().collect::<Vec<[u8; 64]>>();
        desc_bytes.sort_unstable();

        let mut fee_descriptor_bytes = fee_descriptors
            .into_iter()
            .map(<[u8; 40]>::from)
            .collect::<Vec<[u8; 40]>>();
        fee_descriptor_bytes.sort_unstable();
        self.coverage
            == blake2b::stamp_coverage_digest(
                &blake2b::action_descriptor_digest(&desc_bytes),
                &blake2b::stamp_fees_digest(&fee_descriptor_bytes),
            )
    }

    /// Reconstruct the PCD header and verify the proof. Call
    /// [`ProofStamp::is_covering`] first to cheaply predict a mismatch.
    ///
    /// # Soundness
    ///
    /// The parameter is a multiset: order does not matter, multiplicity does.
    /// The header is built from [`Self::tachygram_set`], so the published
    /// [`Self::tachygrams`] are not read here.
    ///
    /// # Errors
    ///
    /// Returns [`ragu_core::Error`] if the proof system fails. A disproved
    /// proof is reported as `Ok(false)`, not an error.
    pub fn verify_proof<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        action_digests: impl IntoIterator<Item = ActionDigest>,
    ) -> Result<bool, ragu_core::Error> {
        let action_set = ActionSetPoly::from_iter(action_digests);

        self.proof
            .verify(rng, (action_set.commit(), self.tachygram_set, self.anchor))
    }
}
