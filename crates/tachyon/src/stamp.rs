//! Stamps and anchors.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]
#![allow(
    clippy::multiple_inherent_impl,
    clippy::same_name_method,
    reason = "todo: take read/write off StampState"
)]

extern crate alloc;

mod aggregator;
pub mod proof;
mod publication;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::error;

pub use aggregator::{AggregatorProof, MergeError, SpanImportError, UnmergeError};
use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Error};
use polynomials::AggregatorRank;
use proof::{
    App, HEADER_SIZE, output,
    transaction::{
        ActionLift, ActionMerge, Actions, FeeFuse, FeeSeed, OutputAction, SpendAction, Transaction,
        TransactionLift,
    },
};
use ragu::{
    Rank as _, WalletRank,
    circuits::polynomials,
    pasta::Pasta,
    pcd::profile::{Aggregator, Profiled},
    udon::{curve::Affine as _, field::Field as _},
};
use rand_core::CryptoRng;

use crate::{
    ActionSetPoly, Note, TachygramSetPoly, action,
    bridge_hash::bridge_hash,
    bundle::StateByte,
    constants::MAX_STAMP_TACHYGRAMS,
    digest::{blake2b, poseidon},
    effect,
    entropy::ActionEntropy,
    fee,
    keys::{ProofAuthorizingKey, private},
    pasta::{EpAffine, Fp},
    primitives::{ActionDigest, ActionSetCommit, Anchor, Tachygram, TachygramSetCommit},
    serialization::{read_compactsize, write_compactsize},
    stamp::proof::{delegation, pool, spend, spendable},
    value, witness,
};

pub(crate) mod stamp_sealed {
    pub trait Sealed {}

    impl Sealed for super::Autonome {}
    impl Sealed for super::Stamp<super::Uncompressed> {}
    impl Sealed for super::Aggregate {}
    impl Sealed for () {}
}

/// Consensus wire states of a bundle's stamp.
///
/// These are [`Autonome`], [`Aggregate`], and `()` once stripped.
/// A stripped bundle's proof is carried by an aggregate whose
/// [`Stamp::adjuncts`] lists its transaction's txid. A [`Stamp`] with an
/// [`Uncompressed`] proof is not a wire state.
pub trait StampState: stamp_sealed::Sealed {
    /// Number of other bundles this stamp lists. Only aggregates have a list.
    fn n_adjuncts(&self) -> usize {
        0
    }

    /// A stamp's `hStampTachyon`. See [`blake2b::stamp_digest`].
    ///
    /// A stripped stamp hashes an empty input.
    fn stamp_digest(&self) -> [u8; 32];

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

impl StampState for () {
    fn stamp_digest(&self) -> [u8; 32] {
        *blake2b::STAMP_DIGEST_EMPTY
    }

    fn state_byte() -> StateByte {
        StateByte::Stripped
    }

    fn read<R: Read>(_reader: &mut R) -> io::Result<Self> {
        Ok(())
    }

    fn write<W: Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }
}

/// The wallet publication, which covers only its carrying bundle.
pub type Autonome = Stamp<Compressed>;

/// An aggregator publication, carrying the txids of the other bundles it
/// covers.
pub type Aggregate =
    Stamp<ragu::CompressedProof<Profiled<Pasta, Aggregator<HEADER_SIZE>>>, BTreeSet<[u8; 32]>>;

fn read_frame<R: Read>(mut reader: R, length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_frame<W: Write>(mut writer: W, bytes: &[u8], length: usize) -> io::Result<()> {
    if bytes.len() != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected proof length",
        ));
    }
    writer.write_all(bytes)
}

impl<P, A> Stamp<P, A> {
    fn write_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.anchor.write(&mut writer)?;
        self.tachygram_set.write(writer)
    }
}

impl Stamp<Uncompressed> {
    /// Read a full wallet stamp for private handoff.
    ///
    /// # Errors
    /// Returns an error for truncated or invalid fields or proof bytes.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let anchor = Anchor::read(&mut reader)?;
        let tachygram_set = TachygramSetCommit::read(&mut reader)?;
        let bytes = read_frame(reader, Uncompressed::encoded_len())?;
        let proof = Uncompressed::from_bytes(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        Ok(Self {
            anchor,
            tachygram_set,
            adjuncts: (),
            proof: Box::new(proof),
        })
    }

    /// Write the full wallet stamp without a consensus state byte.
    ///
    /// # Errors
    /// Returns an error if encoding or writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.write_header(&mut writer)?;
        write_frame(
            writer,
            &self
                .proof
                .to_bytes()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?,
            Uncompressed::encoded_len(),
        )
    }
}

impl StampState for Autonome {
    fn state_byte() -> StateByte {
        StateByte::Stamped
    }

    fn stamp_digest(&self) -> [u8; 32] {
        #[expect(
            clippy::expect_used,
            reason = "a proved or decoded stamp proof is encodable"
        )]
        let bytes = self.proof.to_bytes().expect("stamp proof is encodable");
        blake2b::stamp_proof_digest(
            self.anchor.0.to_bytes(),
            self.tachygram_set.as_ref().to_bytes(),
            &bytes,
        )
    }

    fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let anchor = Anchor::read(&mut *reader)?;
        let tachygram_set = TachygramSetCommit::read(&mut *reader)?;
        let bytes = read_frame(reader, <Compressed>::encoded_len::<WalletRank>())?;
        let proof = Compressed::from_bytes(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        Ok(Self {
            anchor,
            tachygram_set,
            adjuncts: (),
            proof: Box::new(proof),
        })
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write_header(&mut *writer)?;
        write_frame(
            writer,
            &self
                .proof
                .to_bytes()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?,
            Compressed::encoded_len::<WalletRank>(),
        )
    }
}

impl StampState for Aggregate {
    fn n_adjuncts(&self) -> usize {
        self.adjuncts.len()
    }

    fn state_byte() -> StateByte {
        StateByte::Aggregated
    }

    fn stamp_digest(&self) -> [u8; 32] {
        #[expect(
            clippy::expect_used,
            reason = "a proved or decoded stamp proof is encodable"
        )]
        let bytes = self.proof.to_bytes().expect("stamp proof is encodable");
        let digest = blake2b::stamp_proof_digest(
            self.anchor.0.to_bytes(),
            self.tachygram_set.as_ref().to_bytes(),
            &bytes,
        );
        blake2b::stamp_digest(&self.adjuncts, &digest)
    }

    fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let anchor = Anchor::read(&mut *reader)?;
        let tachygram_set = TachygramSetCommit::read(&mut *reader)?;
        let adjuncts = {
            let n_adjuncts = usize::try_from(read_compactsize(&mut *reader)?)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            // Each adjunct and the carrying bundle hold at least a fee change.
            if n_adjuncts + 1 > MAX_STAMP_TACHYGRAMS {
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

        let bytes = read_frame(
            reader,
            <ragu::CompressedProof<Profiled<Pasta, Aggregator<HEADER_SIZE>>>>::encoded_len::<
                AggregatorRank,
            >(),
        )?;
        let proof = ragu::CompressedProof::from_bytes(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        Ok(Self {
            anchor,
            tachygram_set,
            adjuncts,
            proof: Box::new(proof),
        })
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write_header(&mut *writer)?;
        write_compactsize(
            &mut *writer,
            u64::try_from(self.adjuncts.len()).map_err(|_err| {
                io::Error::new(io::ErrorKind::InvalidData, "adjunct count exceeds u64")
            })?,
        )?;
        for txid in &self.adjuncts {
            writer.write_all(txid)?;
        }
        write_frame(
            writer,
            &self
                .proof
                .to_bytes()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?,
            ragu::CompressedProof::<Profiled<Pasta, Aggregator<HEADER_SIZE>>>::encoded_len::<
                AggregatorRank,
            >(),
        )
    }
}

/// Everything needed to produce a [`Stamp`].
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
        let fee_change_note = max_fee_note.fee_change(fee);
        Self {
            spends,
            outputs,
            anchor,
            max_fee_note,
            fee,
            fee_change_note,
        }
    }

    /// Prove a single [`Stamp`] for this plan.
    ///
    /// Returns the stamp and a descriptor-keyed map of tachygram pairs. Each
    /// pair has the smaller tachygram first.
    /// Successful construction does not guarantee that the stamp verifies.
    ///
    /// `spend_pcds` pairs with the planned spends by position. For each
    /// **spend**, [`spend::SpendBind`] derives the live nullifier pair and
    /// [`Stamp::prove_spend`] proves the action at the spendable's
    /// anchor. If that anchor differs from the plan's anchor, the spend comes
    /// with a list of [`AnchorSpan`](pool::AnchorSpan)s and their members
    /// polynomials. [`ActionLift`] moves the spend's actions along each span in
    /// order. The first span must contain the spendable's anchor, each later
    /// span must contain the previous span's `anchor_end`, and the last span
    /// must end at the plan's anchor. For each **output**,
    /// [`Stamp::prove_output`] proves the action at the plan's anchor.
    ///
    /// The planned actions are recursively merged via [`ActionMerge`] into a
    /// single proof, whose coverage is the planned descriptors. [`FeeFuse`]
    /// then applies the fee, or [`FeeSeed`] proves it for a plan with no
    /// actions. The resulting stamp lists no adjuncts and is not rerandomized:
    /// its proof holds the fee step's trace, including the max fee note's
    /// opening and the fee, until [`Stamp::compress`].
    ///
    /// # Errors
    ///
    /// - [`ProveError::MissingPcd`] if the spend PCDs do not match the planned
    ///   spends, or a spend does not reach the plan's anchor.
    /// - [`ProveError::ProofFailed`] if Ragu cannot construct the proof.
    ///
    /// # Panics
    ///
    /// Panics if the max fee note's `rcm` is zero, or if the plan has no
    /// actions and the max fee note's value is nonzero.
    #[expect(
        clippy::type_complexity,
        reason = "each spend's secret, spendable and spans; the stamp and its authorization data"
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
            ragu::Pcd<Pasta, WalletRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, WalletRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, WalletRank, pool::AnchorSpan>>,
        )>,
    ) -> Result<
        (
            Stamp<Uncompressed>,
            BTreeMap<action::Descriptor, (Tachygram, Tachygram)>,
        ),
        ProveError,
    > {
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
                Stamp::prove_spend(rng, app, theta, bind_pcd, *pak)
                    .map_err(ProveError::ProofFailed)?;
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
                Stamp::prove_output(rng, app, theta, rcv, note, self.anchor)
                    .map_err(ProveError::ProofFailed)?;
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

        let (proof, (_, anchor)) = pcd.into_parts();
        tachygrams.insert(change);
        let tachygram_set = tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();
        Ok((
            Stamp {
                anchor,
                tachygram_set,
                adjuncts: (),
                proof: Box::new(proof),
            },
            descriptors,
        ))
    }
}

/// Errors that can occur while proving a stamp.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ProveError {
    /// Missing PCD inputs for the operation.
    #[display("missing pcd inputs: {_0}")]
    MissingPcd(Box<dyn error::Error + Send + Sync + 'static>),
    /// Proof construction failed; carries the underlying Ragu error.
    #[display("proof failed: {_0}")]
    ProofFailed(ragu::Error),
}

/// An uncompressed Ragu proof.
pub type Uncompressed = ragu::Proof<Pasta, WalletRank>;

/// A compressed Ragu proof.
pub type Compressed = ragu::CompressedProof<Pasta>;

/// A stamp carrying an anchor, a tachygram set commitment, and a proof.
///
/// The stamp does not store the PCD header: the verifier reconstructs
/// `(tachygram_bridge, anchor)` from the trailer and checks both output
/// commitments against the claimed action digests and [`Self::tachygram_set`].
///
/// Wallets prove and lift [`Uncompressed`] proofs, and [`Self::compress`]
/// rerandomizes one and publishes it as a [`Compressed`] proof. An aggregator
/// decompresses a compressed wallet bundle into an [`AggregatorProof`], lifts,
/// merges and unmerges there, and compresses the result into Ragu's compressed
/// proof under the aggregator profile. Both profiles publish compressed proofs
/// on the wire; only wallet publications can be decompressed.
///
/// Verify every received stamp before extending it. Draw randomness for every
/// proving call from an unpredictable source. A full proof holds in the clear
/// its last step's trace and its inputs' commitments and challenges. Proving
/// and lifting do not rerandomize, so a caller handing a full stamp to anyone
/// but the owner of its notes rerandomizes it first with
/// [`Stamp::rerandomize`].
#[derive(Clone, Debug)]
pub struct Stamp<P, A = ()> {
    /// The historic pool state for which this stamp is valid.
    pub anchor: Anchor,

    /// The commitment to the covered bundles' tachygram union.
    pub tachygram_set: TachygramSetCommit,

    /// Only aggregates list other covered transactions by txid,
    /// with `()` instead of a list on a wallet stamp. The bundle carrying this
    /// stamp is never listed.
    ///
    /// [`AggregatorProof::merge`] and [`AggregatorProof::unmerge`] write the
    /// list. Neither the stamp proof nor a signature binds it; it enters only
    /// `hStampTachyon`.
    pub adjuncts: A,

    /// The stamp's Ragu proof.
    #[debug(skip)]
    pub proof: Box<P>,
}

impl Stamp<Uncompressed> {
    /// Proves a single output action, returning `(digests, tachygrams,
    /// anchor, proof, pair)`. The proof is not rerandomized.
    ///
    /// [`output::OutputBind`] settles the tachygram pair, then [`OutputAction`]
    /// derives `alpha` from `theta` and the bound `cm`, proves the action over
    /// the pair, and enforces the tachygram set. Both tachygrams
    /// are returned for publication in the bundle's authorization data.
    /// `digests` holds the proved action's digest.
    ///
    /// # Errors
    ///
    /// Returns [`ragu::Error`] if a proof-system step fails.
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
        ragu::Error,
    > {
        let (bind_pcd, ()) = app.seed(
            rng,
            output::OutputBind,
            witness::output_bind(((), ()), note, rcv),
        )?;
        let (cm, pad, cv) = *bind_pcd.data();
        let pair = (cm.min(pad), cm.max(pad));
        let alpha = theta.randomizer::<effect::Output>(note.commitment());
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        // The successful bind step establishes a non-identity cv; an identity
        // rk would require finding a preimage of the randomizer hash.
        let digest = ActionDigest::from(poseidon::action_digest(
            EpAffine::from(cv),
            EpAffine::from(rk),
            (Fp::from(pair.0), Fp::from(pair.1)),
        ));
        let tachygrams = BTreeSet::from_iter([cm, pad]);

        let (pcd, ()) = app.fuse(
            rng,
            OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            app.bootstrap_proof().clone().carry::<()>(()),
        )?;

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
    /// the action `(cv, rk, pair)`, and enforces the tachygram set over the
    /// pair. The spend's `anchor` is taken as the stamp's anchor; chain
    /// validation lives inside the spendable lineage. `digests` holds the
    /// proved action's digest.
    ///
    /// # Errors
    ///
    /// Returns [`ragu::Error`] if a proof-system step fails.
    #[expect(
        clippy::type_complexity,
        reason = "the digests, tachygrams, anchor and proof of one stamp"
    )]
    fn prove_spend<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        theta: ActionEntropy,
        bind_pcd: ragu::Pcd<Pasta, WalletRank, spend::SpendHeader>,
        pak: ProofAuthorizingKey,
    ) -> Result<
        (
            BTreeSet<ActionDigest>,
            BTreeSet<Tachygram>,
            Anchor,
            Box<Uncompressed>,
            (Tachygram, Tachygram),
        ),
        ragu::Error,
    > {
        let (cm, nf_current, nf_next, anchor, _pk, cv) = *bind_pcd.data();
        let alpha = theta.randomizer::<effect::Spend>(cm);
        let (tg_current, tg_next) = (Tachygram::from(nf_current), Tachygram::from(nf_next));
        let pair = (tg_current.min(tg_next), tg_current.max(tg_next));
        let rk = pak.ak.derive_action_public(&alpha);
        // The successful bind step establishes a non-identity cv; an identity
        // rk would require finding a preimage of the randomizer hash.
        let digest = ActionDigest::from(poseidon::action_digest(
            EpAffine::from(cv),
            EpAffine::from(rk),
            (Fp::from(pair.0), Fp::from(pair.1)),
        ));

        let tachygrams = BTreeSet::from_iter([tg_current, tg_next]);

        let (pcd, ()) = app.fuse(
            rng,
            SpendAction,
            witness::spend_action((*bind_pcd.data(), ()), theta, pak),
            bind_pcd,
            app.bootstrap_proof().clone().carry::<()>(()),
        )?;

        Ok((
            BTreeSet::from_iter([digest]),
            tachygrams,
            anchor,
            Box::new(pcd.proof().clone()),
            pair,
        ))
    }

    /// Advances the stamp's anchor along `spans`. The first span must contain
    /// the stamp's anchor, and each later span must contain the previous span's
    /// `anchor_end`.
    ///
    /// # Errors
    ///
    /// Returns [`ragu::Error`] if a proof-system operation fails.
    fn prove_lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        action_digests: impl IntoIterator<Item = ActionDigest>,
        spans: Vec<ragu::Pcd<Pasta, WalletRank, pool::AnchorSpan>>,
    ) -> Result<Self, ragu::Error> {
        let action_set = action_digests.into_iter().collect::<ActionSetPoly>();
        let bridge = bridge_hash(self.tachygram_set.into()).into();
        let mut transaction_pcd = self.proof.carry::<Transaction>((bridge, self.anchor));
        for span in spans {
            transaction_pcd = app
                .fuse(
                    rng,
                    TransactionLift,
                    witness::transaction_lift(
                        (*transaction_pcd.data(), *span.data()),
                        action_set.clone(),
                    ),
                    transaction_pcd,
                    span,
                )?
                .0;
        }
        let (proof, (_, anchor)) = transaction_pcd.into_parts();

        Ok(Self {
            anchor,
            tachygram_set: self.tachygram_set,
            adjuncts: (),
            proof: Box::new(proof),
        })
    }

    /// Advances the stamp's anchor along `spans`, computing the action digests
    /// from the covered action and fee descriptors.
    /// Successful construction does not guarantee that the lifted stamp
    /// verifies.
    ///
    /// The lifted proof is not rerandomized: it holds the last lift's trace,
    /// including the prior header and the span's, until
    /// [`Stamp::compress`]. If `spans` is empty, returns the original
    /// stamp without inspecting the descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`ragu::Error`] if a proof-system operation fails.
    ///
    /// # Panics
    ///
    /// Panics when digesting a hand-built map holding an identity `cv` or `rk`.
    pub fn lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        descriptors: &BTreeMap<action::Descriptor, (Tachygram, Tachygram)>,
        fee_descriptors: &BTreeMap<fee::Descriptor, Tachygram>,
        spans: Vec<ragu::Pcd<Pasta, WalletRank, pool::AnchorSpan>>,
    ) -> Result<Self, ragu::Error> {
        if spans.is_empty() {
            return Ok(self);
        }
        let mut action_digests = BTreeSet::new();
        for (descriptor, &pair) in descriptors {
            action_digests.insert(descriptor.digest(pair));
        }
        for (descriptor, &change) in fee_descriptors {
            action_digests.insert(descriptor.digest(change));
        }

        self.prove_lift(rng, app, action_digests, spans)
    }

    /// Rerandomizes the stamp's full proof for the same header, using fresh
    /// randomness and the application's shared bootstrap proof.
    ///
    /// Call this before handing a full stamp to anyone but the owner of its
    /// notes: proving and lifting leave the last step's trace in the clear.
    /// [`Self::compress`] rerandomizes on its own.
    ///
    /// # Errors
    ///
    /// Returns [`ragu::Error`] if the proof system fails.
    pub fn rerandomize<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
    ) -> Result<Self, ragu::Error> {
        let bridge = bridge_hash(self.tachygram_set.into()).into();
        let pcd = self.proof.carry::<Transaction>((bridge, self.anchor));
        let (proof, _) = app.rerandomize(pcd, rng)?.into_parts();
        Ok(Self {
            proof: Box::new(proof),
            ..self
        })
    }

    /// Rerandomizes the stamp's proof and compresses it for publication.
    ///
    /// The proof carries this stamp's own header, the bridge hash of
    /// [`Self::tachygram_set`] and [`Self::anchor`]. A trailer that does not
    /// match the proof yields an error or a publication that does not verify.
    ///
    /// # Errors
    ///
    /// Returns [`ragu::Error`] if the proof system fails.
    pub fn compress<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
    ) -> Result<Stamp<Compressed>, ragu::Error> {
        let bridge = bridge_hash(self.tachygram_set.into()).into();
        let pcd = self.proof.carry::<Transaction>((bridge, self.anchor));
        let refreshed = app.rerandomize(pcd, &mut *rng)?;
        let (compressed, _) = app.compress(&refreshed, rng)?.into_parts();
        Ok(Stamp {
            anchor: self.anchor,
            tachygram_set: self.tachygram_set,
            adjuncts: (),
            proof: Box::new(compressed),
        })
    }
}

impl Stamp<Uncompressed> {
    /// Reconstruct the PCD header and verify the full proof by compressing it.
    ///
    /// # Soundness
    ///
    /// Verification checks the [`Transaction`] header at [`Self::anchor`] with
    /// the [`bridge_hash`] of [`Self::tachygram_set`]. It matches the two
    /// online commitments to the accumulator of `action_digests` and the
    /// supplied tachygram accumulator. Each fixes its [set
    /// polynomial](crate::collections::multiset) and thus its roots with
    /// multiplicity.
    ///
    /// Bundle coverage
    /// ([`Bundle::verify_covered`](crate::bundle::Bundle::verify_covered)) and
    /// anchor eligibility are checked separately.
    ///
    /// # Errors
    ///
    /// Returns [`ragu::Error`] if the proof system fails. A disproved
    /// proof is reported as `Ok(false)`, not an error.
    pub fn verify_proof<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        action_digests: impl IntoIterator<Item = ActionDigest>,
    ) -> Result<bool, ragu::Error> {
        let Some(actions) = action_commit(action_digests) else {
            return Ok(false);
        };
        let bridge = bridge_hash(self.tachygram_set.into()).into();
        let pcd = self
            .proof
            .as_ref()
            .clone()
            .carry::<Transaction>((bridge, self.anchor));
        if pcd.commitments() != [actions.into(), self.tachygram_set.into()] {
            return Ok(false);
        }
        let compressed = match app.compress(&pcd, rng) {
            Ok(compressed) => compressed,
            Err(ragu::Error::InvalidWitness(_)) => return Ok(false),
            Err(error) => return Err(error),
        };
        app.verify_compressed(&compressed)
    }
}

impl Stamp<Compressed> {
    /// Reconstruct the PCD header and verify the compressed wallet proof.
    ///
    /// # Soundness
    ///
    /// As for the [`Uncompressed`] proof's `verify_proof`.
    ///
    /// # Errors
    ///
    /// Returns [`ragu::Error`] if the proof system fails. A disproved
    /// proof is reported as `Ok(false)`, not an error.
    pub fn verify_proof(
        &self,
        app: &App<'_>,
        action_digests: impl IntoIterator<Item = ActionDigest>,
    ) -> Result<bool, ragu::Error> {
        let Some(actions) = action_commit(action_digests) else {
            return Ok(false);
        };
        publication::verified_transaction(
            app,
            &self.proof,
            (actions, self.tachygram_set, self.anchor),
        )
    }
}

/// The accumulator of `action_digests`, or `None` for more digests than one
/// set polynomial holds: those match no commitment, so every `verify_proof`
/// disproves them without building their polynomial.
fn action_commit(
    action_digests: impl IntoIterator<Item = ActionDigest>,
) -> Option<ActionSetCommit> {
    let digests: Vec<ActionDigest> = action_digests.into_iter().collect();
    (digests.len() < WalletRank::num_coeffs()).then(|| ActionSetPoly::from_iter(digests).commit())
}
