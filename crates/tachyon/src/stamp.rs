//! Stamps and anchors.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]
#![allow(
    clippy::multiple_inherent_impl,
    clippy::same_name_method,
    reason = "todo: take read/write off StampState"
)]

extern crate alloc;

pub mod proof;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::error;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, PartialEq};
use proof::{
    App, HEADER_SIZE, bridge_hash, output,
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

/// The tachygrams and fee of a stripped bundle. Its stamp proof is carried by
/// an aggregate whose [`ProofStamp::adjuncts`] lists the txid of this bundle's
/// transaction.
#[derive(Clone, Debug, PartialEq, TotalEq)]
pub struct StrippedStamp {
    /// The fee of the bundle that carries this stamp.
    pub fee: value::Positive,

    /// The carrying bundle's `vTachygrams`: each action's tachygram pair in
    /// action order, then the fee change note commitment.
    pub tachygrams: Vec<Tachygram>,
}

/// Bundle states that carry a stamp: [`ProofStamp`] or [`StrippedStamp`].
/// The intermediate [`Unproven`] state has no stamp.
pub trait StampState: BundleState {
    /// A stamp's `hStampTachyon`. See [`blake2b::stamp_digest`].
    ///
    /// A [`StrippedStamp`] has no adjunct list and no stamp proof, and passes
    /// `hStampAdjunctsTachyon` of the empty list and
    /// [`blake2b::STAMP_PROOF_DIGEST_EMPTY`].
    fn stamp_digest(&self) -> [u8; 32];

    /// The fee of the bundle that carries this stamp.
    fn fee(&self) -> value::Positive;

    /// The carrying bundle's `vTachygrams`: each action's tachygram pair in
    /// action order, then the fee change note commitment.
    fn tachygrams(&self) -> &[Tachygram];

    /// The `tachyonBundleState` wire byte for this state.
    fn state_byte() -> StateByte
    where
        Self: Sized;

    /// Read the stamp trailer of a bundle with `n_actions` actions from the
    /// consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or the trailer is not a canonical
    /// encoding of this state.
    fn read<R: Read>(reader: &mut R, n_actions: usize) -> io::Result<Self>
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

/// Read the prefix both stamp trailers share: `vTachygrams`, then
/// `vFeeTachyon`. `vTachygrams` holds two tachygrams per action, then the fee
/// change, and rejects a tachygram that repeats an earlier one. Each action's
/// pair may hold its tachygrams in either order.
fn read_trailer_prefix<R: Read>(
    reader: &mut R,
    n_actions: usize,
) -> io::Result<(Vec<Tachygram>, value::Positive)> {
    let n_tachygrams = 2 * n_actions + 1;
    let mut tachygrams = Vec::new();
    let mut seen = BTreeSet::new();
    for _ in 0..n_tachygrams {
        let tg = Tachygram::read(&mut *reader)?;
        if !seen.insert(tg) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tachygrams are not unique",
            ));
        }
        tachygrams.push(tg);
    }

    let fee = {
        let mut bytes = [0u8; size_of::<u64>()];
        reader.read_exact(&mut bytes)?;
        value::Positive::try_from(u64::from_le_bytes(bytes))
            .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "fee out of range"))
    }?;

    Ok((tachygrams, fee))
}

/// Write the prefix both stamp trailers share. See [`read_trailer_prefix`].
fn write_trailer_prefix<W: Write>(
    writer: &mut W,
    tachygrams: &[Tachygram],
    fee: value::Positive,
) -> io::Result<()> {
    for tg in tachygrams {
        tg.write(&mut *writer)?;
    }
    writer.write_all(&u64::from(fee).to_le_bytes())
}

impl StampState for StrippedStamp {
    fn stamp_digest(&self) -> [u8; 32] {
        blake2b::stamp_digest(
            &self
                .tachygrams
                .iter()
                .map(|&tg| Fp::from(tg).to_bytes())
                .collect::<Vec<_>>(),
            u64::from(self.fee),
            &blake2b::stamp_adjuncts_digest(&[]),
            &blake2b::STAMP_PROOF_DIGEST_EMPTY,
        )
    }

    fn fee(&self) -> value::Positive {
        self.fee
    }

    fn tachygrams(&self) -> &[Tachygram] {
        &self.tachygrams
    }

    fn state_byte() -> StateByte {
        StateByte::StrippedStamp
    }

    fn read<R: Read>(reader: &mut R, n_actions: usize) -> io::Result<Self> {
        Self::read(reader, n_actions)
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write(writer)
    }
}

impl StrippedStamp {
    /// Read the stamp trailer of a bundle with `n_actions` actions from the
    /// consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails, a tachygram repeats, or the fee
    /// exceeds `MAX_MONEY`.
    pub fn read<R: Read>(mut reader: R, n_actions: usize) -> io::Result<Self> {
        let (tachygrams, fee) = read_trailer_prefix(&mut reader, n_actions)?;
        Ok(Self { fee, tachygrams })
    }

    /// Write the stamp trailer to the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_trailer_prefix(&mut writer, &self.tachygrams, self.fee)
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
        app: &App<'_>,
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
        app: &App<'_>,
        header: (ActionSetCommit, TachygramSetCommit, Anchor),
    ) -> Result<bool, ragu_core::Error> {
        let bridge = bridge_hash(header.1.as_ref().to_affine());
        let pcd = self.clone().carry::<Stamp>((bridge.into(), header.2));
        let [action_slot, tachygram_slot] = pcd.commitments();
        if action_slot != Eq::from(header.0).to_affine()
            || tachygram_slot != Eq::from(header.1).to_affine()
        {
            return Ok(false);
        }
        let compressed = match app.compress(&pcd, rng) {
            Ok(compressed) => compressed,
            Err(ragu_core::Error::InvalidWitness(_)) => return Ok(false),
            Err(error) => return Err(error),
        };
        app.verify_compressed(&compressed)
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
        app: &App<'_>,
        header: (ActionSetCommit, TachygramSetCommit, Anchor),
    ) -> Result<bool, ragu_core::Error> {
        let [action_slot, tachygram_slot] = self.online_commitments();
        if action_slot != Eq::from(header.0).to_affine()
            || tachygram_slot != Eq::from(header.1).to_affine()
        {
            return Ok(false);
        }
        let bridge = bridge_hash(header.1.as_ref().to_affine());
        app.verify_compressed(&self.clone().carry::<Stamp>((bridge.into(), header.2)))
    }
}

impl<P: Proof> StampState for ProofStamp<P> {
    fn stamp_digest(&self) -> [u8; 32] {
        #[expect(
            clippy::expect_used,
            reason = "a proved or decoded stamp proof is encodable"
        )]
        let proof = self.proof.to_bytes().expect("stamp proof is encodable");

        blake2b::stamp_digest(
            &self
                .tachygrams
                .iter()
                .map(|&tg| Fp::from(tg).to_bytes())
                .collect::<Vec<_>>(),
            u64::from(self.fee),
            &blake2b::stamp_adjuncts_digest(&self.adjuncts.iter().copied().collect::<Vec<_>>()),
            &blake2b::stamp_proof_digest(
                self.anchor.0.to_bytes(),
                self.tachygram_set.as_ref().to_affine().to_bytes(),
                proof.as_ref(),
            ),
        )
    }

    fn fee(&self) -> value::Positive {
        self.fee
    }

    fn tachygrams(&self) -> &[Tachygram] {
        &self.tachygrams
    }

    fn state_byte() -> StateByte {
        StateByte::ProofStamp
    }

    fn read<R: Read>(reader: &mut R, n_actions: usize) -> io::Result<Self> {
        Self::read(reader, n_actions)
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write(writer)
    }
}

impl<P: Proof> ProofStamp<P> {
    /// Read the stamp trailer of a bundle with `n_actions` actions from the
    /// consensus wire format. The adjunct list and the proof blob each have a
    /// compactSize prefix. The proof is bounded by the proof type's encoded
    /// length.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails, a tachygram repeats, any component is
    /// not a canonical encoding, the adjunct txids are not strictly ascending,
    /// or the adjuncts and actions hold more tachygrams than one set
    /// polynomial.
    pub fn read<R: Read>(mut reader: R, n_actions: usize) -> io::Result<Self> {
        let (tachygrams, fee) = read_trailer_prefix(&mut reader, n_actions)?;

        let anchor = Anchor::read(&mut reader)?;

        // Full validation confirms this against the covered bundles.
        let tachygram_set = {
            let point = serialization::read_eq_affine(&mut reader)?;
            if point.is_identity() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tachygram set commitment is the identity",
                ));
            }
            TachygramSetCommit::from(Eq::from(point))
        };

        let adjuncts = {
            let n_adjuncts = usize::try_from(serialization::read_compactsize(&mut reader)?)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            // Each adjunct holds at least its fee change, a root of the covered
            // set polynomial beside this bundle's pairs and fee change.
            if 2 * n_actions + n_adjuncts + 1 > ProductionRank::num_coeffs() - 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many adjuncts",
                ));
            }
            let mut adjuncts = BTreeSet::new();
            for _ in 0..n_adjuncts {
                let mut txid = [0u8; 32];
                reader.read_exact(&mut txid)?;
                if adjuncts.last().is_some_and(|last| *last >= txid) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "adjunct txids are not strictly ascending",
                    ));
                }
                adjuncts.insert(txid);
            }
            adjuncts
        };

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
            anchor,
            tachygram_set,
            tachygrams,
            adjuncts,
            proof: Box::new(proof),
            fee,
        })
    }

    /// Write the stamp trailer to the consensus wire format. The adjunct list
    /// and the proof blob each have a compactSize prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails or the proof has no encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_trailer_prefix(&mut writer, &self.tachygrams, self.fee)?;
        self.anchor.write(&mut writer)?;
        serialization::write_eq_affine(&mut writer, &self.tachygram_set.as_ref().to_affine())?;
        serialization::write_compactsize(
            &mut writer,
            u64::try_from(self.adjuncts.len()).map_err(|_err| {
                io::Error::new(io::ErrorKind::InvalidData, "adjunct count exceeds u64")
            })?,
        )?;
        for txid in &self.adjuncts {
            writer.write_all(txid)?;
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
/// The statement includes each action's descriptor and tachygram pair, the fee
/// descriptor, and the `anchor`. The planned witnesses are each action's
/// `theta` and `rcv`, each output's `note`, and the max fee note with the `fee`
/// it pays and the derived fee change note. A spend's note comes from its
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
    /// Its tachygram pairs are in descriptor order, each smaller tachygram
    /// first.
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
    /// actions. The stamp lists no adjuncts.
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
        app: &App<'_>,
        pak: &ProofAuthorizingKey,
        spend_pcds: Vec<(
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
        )>,
    ) -> Result<ProofStamp<Uncompressed>, ProveError> {
        let change = Tachygram::from(self.fee_change_note.commitment());

        // Each entry pairs leaf stamp components with the descriptor of its
        // covered action; merges concatenate both.
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
            let (bind_pcd, ()) = app
                .fuse(
                    rng,
                    spend::SpendBind,
                    witness::spend_bind((*spendable_pcd.data(), *secret_pcd.data()), rcv),
                    spendable_pcd,
                    secret_pcd,
                )
                .map_err(ProveError::ProofFailed)?;

            let (digests, tachygrams, spend_anchor, spend_proof, pair) =
                ProofStamp::prove_spend(rng, app, theta, bind_pcd, *pak)?;
            let mut stamp_pcd = spend_proof.carry::<Actions>(spend_anchor);
            for span in spans {
                stamp_pcd = app
                    .fuse(rng, ActionLift, (), stamp_pcd, span)
                    .map_err(ProveError::ProofFailed)?
                    .0;
            }

            let (proof, anchor) = stamp_pcd.into_parts();
            entries.push((
                BTreeMap::from([(desc, pair)]),
                digests,
                tachygrams,
                anchor,
                Box::new(proof),
            ));
        }

        for (desc, theta, note, rcv) in self.outputs {
            let (digests, tachygrams, anchor, proof, pair) =
                ProofStamp::prove_output(rng, app, theta, rcv, note, self.anchor)?;
            entries.push((
                BTreeMap::from([(desc, pair)]),
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

                let (pcd, ()) = app
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

                let merged_descs = left_desc.into_iter().chain(right_desc).collect();

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
                let (pcd, ()) = app
                    .seed(
                        rng,
                        FeeSeed,
                        witness::fee_seed(((), ()), self.max_fee_note, self.anchor),
                    )
                    .map_err(ProveError::ProofFailed)?;
                (pcd, BTreeMap::new(), BTreeSet::new())
            },
            Some((descriptors, digests, tachygrams, anchor, merged_proof)) => {
                let (pcd, ()) = app
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
                        app.bootstrap_proof().clone().carry::<()>(()),
                    )
                    .map_err(ProveError::ProofFailed)?;
                (pcd, descriptors, tachygrams)
            },
        };

        let (proof, (_, anchor)) = app
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
            anchor,
            tachygram_set,
            tachygrams: descriptors
                .into_values()
                .flat_map(<[Tachygram; 2]>::from)
                .chain([change])
                .collect(),
            adjuncts: BTreeSet::new(),
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
/// here. A verifier must reconstruct the header from public data and check the
/// proof's output slots against the covered actions and
/// [`Self::tachygram_set`].
///
/// Only the uncompressed proof type supports lifting, merging and
/// unmerging. Compressed stamps support reading, writing and verification.
#[derive(Clone, Debug)]
pub struct ProofStamp<P: Proof> {
    /// The historic pool state for which this stamp is valid.
    pub anchor: Anchor,

    /// The commitment to the covered bundles' tachygram union.
    pub tachygram_set: TachygramSetCommit,

    /// The carrying bundle's `vTachygrams`: each action's tachygram pair in
    /// action order, then the fee change note commitment.
    pub tachygrams: Vec<Tachygram>,

    /// The txids of the other transactions whose bundles this stamp covers,
    /// empty for an autonome. The bundle carrying this stamp is never listed.
    ///
    /// [`Self::merge`] and [`Self::unmerge`] write the list. Neither the stamp
    /// proof nor a signature binds it; it enters only `hStampTachyon`, through
    /// `hStampAdjunctsTachyon`.
    pub adjuncts: BTreeSet<[u8; 32]>,

    /// The full or compressed Ragu proof.
    #[debug(skip)]
    pub proof: Box<P>,

    /// The fee of the bundle that carries this stamp.
    pub fee: value::Positive,
}

impl ProofStamp<Uncompressed> {
    /// Proves a single output action, returning `(digests, tachygrams,
    /// anchor, proof, pair)`. The proof is not rerandomized.
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
        app: &App<'_>,
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
            (Tachygram, Tachygram),
        ),
        ProveError,
    > {
        let (bind_pcd, ()) = app
            .seed(
                rng,
                output::OutputBind,
                witness::output_bind(((), ()), note, rcv),
            )
            .map_err(ProveError::ProofFailed)?;
        let (cm, pad, cv) = *bind_pcd.data();
        let pair = (cm.min(pad), cm.max(pad));
        let alpha = theta.randomizer::<effect::Output>(note.commitment());
        let digest = ActionDigest::new(
            cv,
            private::ActionSigningKey::new(&alpha).derive_action_public(),
            pair,
        )
        .map_err(ProveError::ActionDigest)?;
        let tachygrams = BTreeSet::from_iter([cm, pad]);

        let (pcd, ()) = app
            .fuse(
                rng,
                OutputAction,
                witness::output_action((*bind_pcd.data(), ()), theta, anchor),
                bind_pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .map_err(ProveError::ProofFailed)?;

        Ok((
            BTreeSet::from_iter([digest]),
            tachygrams,
            anchor,
            Box::new(pcd.proof().clone()),
            pair,
        ))
    }

    /// Proves a single spend action from a bound
    /// [`SpendHeader`](spend::SpendHeader) PCD, returning `(digests,
    /// tachygrams, anchor, proof, pair)`. The proof is not rerandomized.
    ///
    /// The nullifier pair `{nf_current, nf_next}` published for data
    /// availability and the value commitment `cv` are read straight off the
    /// bind header (both derived at [`SpendBind`](spend::SpendBind)).
    /// [`SpendAction`] derives `alpha` from `theta` and the bound `cm`, proves
    /// the action `(cv, rk, pair)`, and enforces the stamp accumulator over the
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
        app: &App<'_>,
        theta: ActionEntropy,
        bind_pcd: ragu::Pcd<Pasta, ProductionRank, spend::SpendHeader>,
        pak: ProofAuthorizingKey,
    ) -> Result<
        (
            BTreeSet<ActionDigest>,
            BTreeSet<Tachygram>,
            Anchor,
            Box<Uncompressed>,
            (Tachygram, Tachygram),
        ),
        ProveError,
    > {
        let (cm, nf_current, nf_next, anchor, _pk, cv) = *bind_pcd.data();
        let alpha = theta.randomizer::<effect::Spend>(cm);
        let (tg_current, tg_next) = (Tachygram::from(nf_current), Tachygram::from(nf_next));
        let pair = (tg_current.min(tg_next), tg_current.max(tg_next));
        let digest = ActionDigest::new(cv, pak.ak.derive_action_public(&alpha), pair)
            .map_err(ProveError::ActionDigest)?;

        let tachygrams = BTreeSet::from_iter([tg_current, tg_next]);

        let (pcd, ()) = app
            .fuse(
                rng,
                SpendAction,
                witness::spend_action((*bind_pcd.data(), ()), theta, pak),
                bind_pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .map_err(ProveError::ProofFailed)?;

        Ok((
            BTreeSet::from_iter([digest]),
            tachygrams,
            anchor,
            Box::new(pcd.proof().clone()),
            pair,
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
        app: &App<'_>,
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

        let left_bridge = bridge_hash(left_tg_poly.commit().as_ref().to_affine());
        let right_bridge = bridge_hash(right_tg_poly.commit().as_ref().to_affine());
        let left_pcd = left_proof.carry::<Stamp>((left_bridge.into(), left_anchor));
        let right_pcd = right_proof.carry::<Stamp>((right_bridge.into(), right_anchor));

        let merged_digests: BTreeSet<ActionDigest> =
            left_digests.union(&right_digests).copied().collect();
        let tachygrams: BTreeSet<Tachygram> =
            left_tachygrams.union(&right_tachygrams).copied().collect();

        let (pcd, ()) = app.fuse(
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
        app: &App<'_>,
        action_digests: impl IntoIterator<Item = ActionDigest>,
        spans: Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Result<Self, ProveError> {
        if spans.is_empty() {
            return Err(ProveError::MissingPcd(
                "no anchor span proof for no anchor advance".into(),
            ));
        }

        let action_set = action_digests.into_iter().collect::<ActionSetPoly>();
        let bridge = bridge_hash(self.tachygram_set.as_ref().to_affine());
        let mut stamp_pcd = self.proof.carry::<Stamp>((bridge.into(), self.anchor));
        for span in spans {
            stamp_pcd = app
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
        let proof = app
            .rerandomize(stamp_pcd, rng)
            .map_err(ProveError::ProofFailed)?
            .proof()
            .clone();

        Ok(Self {
            anchor,
            tachygram_set: self.tachygram_set,
            tachygrams: self.tachygrams,
            adjuncts: self.adjuncts,
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
    ///
    /// # Panics
    ///
    /// Panics if a covered bundle's tachygrams are empty. A read stamp and a
    /// proved stamp always end with the fee change.
    pub fn lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        covered: Vec<(Vec<action::Descriptor>, fee::Descriptor, Vec<Tachygram>)>,
        spans: Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Result<Self, ProveError> {
        let mut action_digests = BTreeSet::new();
        for (descriptors, fee_descriptor, tachygrams) in covered {
            #[expect(
                clippy::expect_used,
                reason = "a covered bundle's tachygrams end with its fee change"
            )]
            let (&fee_change, pairs) = tachygrams
                .split_last()
                .expect("a covered bundle's tachygrams end with its fee change");
            for (descriptor, &pair) in descriptors.iter().zip(pairs.as_chunks::<2>().0) {
                action_digests.insert(
                    descriptor
                        .digest(pair.into())
                        .map_err(ProveError::ActionDigest)?,
                );
            }
            action_digests.insert(
                fee_descriptor
                    .digest(fee_change)
                    .map_err(ProveError::ActionDigest)?,
            );
        }

        self.prove_lift(rng, app, action_digests, spans)
    }

    /// Merges two stamps into one covering stamp.
    ///
    /// Each side pairs a stamp with what it covers of each covered bundle, as
    /// [`Bundle::covered`](crate::Bundle::covered) gives it, from which the
    /// action digests and tachygrams for the merge proof are derived.
    ///
    /// The merged stamp stays with this stamp's bundle and keeps this stamp's
    /// fee. It lists both stamps' adjuncts and `right_txid`, the txid of the
    /// one transaction the right stamp covers without listing, which the
    /// caller takes from that transaction's plan or from the published
    /// transaction.
    ///
    /// This method cannot check `right_txid`. A wrong txid yields an aggregate
    /// that consensus rejects, because its list omits a transaction it covers
    /// and can name one it does not.
    ///
    /// A quotient that has no transaction it covers without listing is not a
    /// valid right stamp; see [`Self::unmerge`].
    ///
    /// # Errors
    ///
    /// Returns [`ProveError`] if an action digest cannot be computed or a
    /// proof-system step fails.
    ///
    /// # Panics
    ///
    /// Panics if a covered bundle's tachygrams are empty. A read stamp and a
    /// proved stamp always end with the fee change.
    #[expect(
        clippy::type_complexity,
        reason = "the stamp, txid and covered bundles of the absorbed side"
    )]
    pub fn merge<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        left_covered: Vec<(Vec<action::Descriptor>, fee::Descriptor, Vec<Tachygram>)>,
        (right_stamp, right_txid, right_covered): (
            Self,
            [u8; 32],
            Vec<(Vec<action::Descriptor>, fee::Descriptor, Vec<Tachygram>)>,
        ),
    ) -> Result<Self, ProveError> {
        let mut left_digests = BTreeSet::new();
        let mut left_tachygrams = BTreeSet::new();
        for (descriptors, fee_descriptor, tachygrams) in left_covered {
            left_tachygrams.extend(tachygrams.iter().copied());
            #[expect(
                clippy::expect_used,
                reason = "a covered bundle's tachygrams end with its fee change"
            )]
            let (&fee_change, pairs) = tachygrams
                .split_last()
                .expect("a covered bundle's tachygrams end with its fee change");
            for (descriptor, &pair) in descriptors.iter().zip(pairs.as_chunks::<2>().0) {
                left_digests.insert(
                    descriptor
                        .digest(pair.into())
                        .map_err(ProveError::ActionDigest)?,
                );
            }
            left_digests.insert(
                fee_descriptor
                    .digest(fee_change)
                    .map_err(ProveError::ActionDigest)?,
            );
        }

        let mut right_digests = BTreeSet::new();
        let mut right_tachygrams = BTreeSet::new();
        for (descriptors, fee_descriptor, tachygrams) in right_covered {
            right_tachygrams.extend(tachygrams.iter().copied());
            #[expect(
                clippy::expect_used,
                reason = "a covered bundle's tachygrams end with its fee change"
            )]
            let (&fee_change, pairs) = tachygrams
                .split_last()
                .expect("a covered bundle's tachygrams end with its fee change");
            for (descriptor, &pair) in descriptors.iter().zip(pairs.as_chunks::<2>().0) {
                right_digests.insert(
                    descriptor
                        .digest(pair.into())
                        .map_err(ProveError::ActionDigest)?,
                );
            }
            right_digests.insert(
                fee_descriptor
                    .digest(fee_change)
                    .map_err(ProveError::ActionDigest)?,
            );
        }

        let (_, tachygrams, anchor, merged_proof) = Self::prove_merge(
            rng,
            app,
            (left_digests, left_tachygrams, self.anchor, self.proof),
            (
                right_digests,
                right_tachygrams,
                right_stamp.anchor,
                right_stamp.proof,
            ),
        )
        .map_err(ProveError::ProofFailed)?;

        let tachygram_set = tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();
        let proof = app
            .rerandomize(
                merged_proof.carry::<Stamp>((
                    bridge_hash(tachygram_set.as_ref().to_affine()).into(),
                    anchor,
                )),
                rng,
            )
            .map_err(ProveError::ProofFailed)?
            .proof()
            .clone();

        let mut adjuncts = self.adjuncts;
        adjuncts.extend(right_stamp.adjuncts);
        adjuncts.insert(right_txid);

        Ok(Self {
            anchor,
            tachygram_set,
            tachygrams: self.tachygrams,
            adjuncts,
            proof: Box::new(proof),
            fee: self.fee,
        })
    }

    /// Divides this stamp by a divisor stamp at the same anchor, removing the
    /// divisor's covered actions, fees and tachygrams.
    ///
    /// Each side pairs a stamp with what it covers of each covered bundle, as
    /// [`Bundle::covered`](crate::Bundle::covered) gives it. The quotient's
    /// action digests and tachygrams are the dividend's less the divisor's.
    /// The quotient stays with this stamp's bundle and keeps this stamp's fee,
    /// fee change and tachygram pairs, undoing a merge of the divisor into this
    /// stamp. A divisor that removes this stamp's bundle leaves a quotient
    /// whose fee, fee change and pairs belong to a bundle it no longer covers.
    /// A divisor that does not divide this stamp fails in the proof system.
    ///
    /// The quotient lists this stamp's adjuncts less the divisor's adjuncts and
    /// `divisor_txid`, the txid of the one transaction the divisor covers
    /// without listing. A divisor this stamp does not list is not rejected.
    ///
    /// A quotient whose divisor removed the bundle that carried the dividend
    /// covers only the transactions it lists. It has no transaction it covers
    /// without listing, so no `divisor_txid` is correct for it, and it is not
    /// a valid divisor. This method accepts it, and the result can list a
    /// transaction it does not cover or omit one it does, which consensus
    /// rejects.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError`] if an action digest cannot be computed or a
    /// proof-system step fails.
    ///
    /// # Panics
    ///
    /// Panics if a covered bundle's tachygrams are empty. A read stamp and a
    /// proved stamp always end with the fee change.
    #[expect(
        clippy::type_complexity,
        reason = "the stamp, txid and covered bundles of the divisor"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "the dividend's and the divisor's digest loops are written in place"
    )]
    pub fn unmerge<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        covered: Vec<(Vec<action::Descriptor>, fee::Descriptor, Vec<Tachygram>)>,
        (divisor_stamp, divisor_txid, divisor_covered): (
            Self,
            [u8; 32],
            Vec<(Vec<action::Descriptor>, fee::Descriptor, Vec<Tachygram>)>,
        ),
    ) -> Result<Self, ProveError> {
        let mut digests = BTreeSet::new();
        let mut tachygrams_all = BTreeSet::new();
        for (descriptors, fee_descriptor, tachygrams) in covered {
            tachygrams_all.extend(tachygrams.iter().copied());
            #[expect(
                clippy::expect_used,
                reason = "a covered bundle's tachygrams end with its fee change"
            )]
            let (&fee_change, pairs) = tachygrams
                .split_last()
                .expect("a covered bundle's tachygrams end with its fee change");
            for (descriptor, &pair) in descriptors.iter().zip(pairs.as_chunks::<2>().0) {
                digests.insert(
                    descriptor
                        .digest(pair.into())
                        .map_err(ProveError::ActionDigest)?,
                );
            }
            digests.insert(
                fee_descriptor
                    .digest(fee_change)
                    .map_err(ProveError::ActionDigest)?,
            );
        }

        let mut divisor_digests = BTreeSet::new();
        let mut divisor_tachygrams = BTreeSet::new();
        for (descriptors, fee_descriptor, tachygrams) in divisor_covered {
            divisor_tachygrams.extend(tachygrams.iter().copied());
            #[expect(
                clippy::expect_used,
                reason = "a covered bundle's tachygrams end with its fee change"
            )]
            let (&fee_change, pairs) = tachygrams
                .split_last()
                .expect("a covered bundle's tachygrams end with its fee change");
            for (descriptor, &pair) in descriptors.iter().zip(pairs.as_chunks::<2>().0) {
                divisor_digests.insert(
                    descriptor
                        .digest(pair.into())
                        .map_err(ProveError::ActionDigest)?,
                );
            }
            divisor_digests.insert(
                fee_descriptor
                    .digest(fee_change)
                    .map_err(ProveError::ActionDigest)?,
            );
        }

        let quotient_action_set = digests
            .difference(&divisor_digests)
            .copied()
            .collect::<ActionSetPoly>();

        let dividend_tachygram_set = tachygrams_all.iter().copied().collect::<TachygramSetPoly>();
        let quotient_tachygram_set = tachygrams_all
            .difference(&divisor_tachygrams)
            .copied()
            .collect::<TachygramSetPoly>();
        let tachygram_set = quotient_tachygram_set.commit();
        let divisor_tachygram_set = divisor_tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>();

        let dividend_bridge = bridge_hash(dividend_tachygram_set.commit().as_ref().to_affine());
        let divisor_bridge = bridge_hash(divisor_tachygram_set.commit().as_ref().to_affine());
        let dividend_pcd = self
            .proof
            .carry::<Stamp>((dividend_bridge.into(), self.anchor));
        let divisor_pcd = divisor_stamp
            .proof
            .carry::<Stamp>((divisor_bridge.into(), divisor_stamp.anchor));

        let (pcd, ()) = app
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

        let anchor = pcd.data().1;
        let proof = app
            .rerandomize(pcd, rng)
            .map_err(ProveError::ProofFailed)?
            .proof()
            .clone();

        Ok(Self {
            anchor,
            tachygram_set,
            tachygrams: self.tachygrams,
            adjuncts: self
                .adjuncts
                .difference(&divisor_stamp.adjuncts)
                .copied()
                .filter(|txid| *txid != divisor_txid)
                .collect(),
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
        app: &App<'_>,
    ) -> Result<ProofStamp<Compressed>, ProveError> {
        let bridge = bridge_hash(self.tachygram_set.as_ref().to_affine());
        let pcd = self.proof.carry::<Stamp>((bridge.into(), self.anchor));
        let (compressed, _) = app
            .compress(&pcd, rng)
            .map_err(ProveError::ProofFailed)?
            .into_parts();
        Ok(ProofStamp {
            anchor: self.anchor,
            tachygram_set: self.tachygram_set,
            tachygrams: self.tachygrams,
            adjuncts: self.adjuncts,
            proof: Box::new(compressed),
            fee: self.fee,
        })
    }
}

impl<P: Proof> ProofStamp<P> {
    /// Reconstruct the PCD header and verify the proof.
    ///
    /// # Soundness
    ///
    /// The parameter is a multiset: order does not matter, multiplicity does.
    /// The header is built from [`Self::tachygram_set`]. The caller confirms
    /// that commitment against the covered bundles' pairs and fee changes.
    ///
    /// # Errors
    ///
    /// Returns [`ragu_core::Error`] if the proof system fails. A disproved
    /// proof is reported as `Ok(false)`, not an error.
    pub fn verify_proof<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        action_digests: impl IntoIterator<Item = ActionDigest>,
    ) -> Result<bool, ragu_core::Error> {
        let action_set = ActionSetPoly::from_iter(action_digests);

        self.proof.verify(
            rng,
            app,
            (action_set.commit(), self.tachygram_set, self.anchor),
        )
    }
}
