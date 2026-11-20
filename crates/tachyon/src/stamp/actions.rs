use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
};
use core::error;

use ragu::udon::field::Field as _;

use super::{
    ActionDigest, ActionEntropy, ActionLift, ActionMerge, Actions, Anchor, App, Box, CryptoRng,
    Debug, Display, Error, FeeFuse, FeeSeed, Fp, Note, Pasta, ProductionRank, ProofAuthorizingKey,
    ProofStamp, Stamp, Tachygram, TachygramSetCommit, Uncompressed, Vec, action, delegation, pool,
    spend, spendable, value, witness,
};

pub(super) struct ActionSets {
    digests: BTreeSet<ActionDigest>,
    tachygrams: BTreeSet<Tachygram>,
}

pub(super) struct ProvedActions {
    pub(super) proof: ActionsProof,
    pub(super) sets: ActionSets,
}

pub(super) struct SpendInput {
    descriptor: action::Descriptor,
    theta: ActionEntropy,
    rcv: value::Trapdoor,
    pak: ProofAuthorizingKey,
    secret: ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
    spendable: ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
    spans: Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
}

/// The action descriptors and their witnesses at one anchor, without a fee.
#[derive(Clone, Debug)]
pub struct ActionsPlan {
    spends: Vec<(action::Descriptor, ActionEntropy, value::Trapdoor)>,
    outputs: Vec<(action::Descriptor, ActionEntropy, Note, value::Trapdoor)>,
    anchor: Anchor,
}

impl ActionsPlan {
    /// Plan all or part of a bundle's actions.
    #[must_use]
    pub const fn new(
        spends: Vec<(action::Descriptor, ActionEntropy, value::Trapdoor)>,
        outputs: Vec<(action::Descriptor, ActionEntropy, Note, value::Trapdoor)>,
        anchor: Anchor,
    ) -> Self {
        Self {
            spends,
            outputs,
            anchor,
        }
    }

    /// Prove and rerandomize the planned actions before applying a fee.
    ///
    /// `spend_pcds` pairs with the planned spends by position. Each spend's
    /// spans advance its spendable anchor to the plan's anchor, in order.
    /// Successful construction does not guarantee that the proof verifies.
    ///
    /// # Errors
    ///
    /// - [`ActionsProveError::NoActions`] if the plan is empty.
    /// - [`ActionsProveError::MissingPcd`] if the spend PCD count differs from
    ///   the planned spend count or a spend does not reach the plan's anchor.
    /// - [`ActionsProveError::ZeroRcm`] if an output note's `rcm` is zero.
    /// - [`ActionsProveError::DuplicateAction`] if two actions share a
    ///   descriptor.
    /// - [`ActionsProveError::ProofFailed`] if Ragu cannot construct the proof.
    ///
    /// # Panics
    ///
    /// Panics if an action's witnesses produce an identity `cv` or `rk`.
    #[expect(
        clippy::type_complexity,
        reason = "each spend has a key, secret, spendable and spans"
    )]
    pub fn prove<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        spend_pcds: Vec<(
            ProofAuthorizingKey,
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
        )>,
    ) -> Result<ActionsProof, ActionsProveError> {
        let spends = Self::check_spends(self.spends, spend_pcds, self.anchor)
            .map_err(ActionsProveError::MissingPcd)?;
        if self
            .outputs
            .iter()
            .any(|&(_, _, note, _)| Fp::from(note.rcm) == Fp::ZERO)
        {
            return Err(ActionsProveError::ZeroRcm);
        }

        let mut descriptors = BTreeSet::new();
        if spends
            .iter()
            .map(|input| input.descriptor)
            .chain(self.outputs.iter().map(|&(desc, ..)| desc))
            .any(|desc| !descriptors.insert(desc))
        {
            return Err(ActionsProveError::DuplicateAction);
        }

        let proved = Self::prove_actions(rng, app, spends, self.outputs, self.anchor)
            .map_err(ActionsProveError::ProofFailed)?
            .ok_or(ActionsProveError::NoActions)?;
        proved
            .proof
            .rerandomize(rng, app)
            .map_err(ActionsProveError::ProofFailed)
    }

    #[expect(
        clippy::type_complexity,
        reason = "each spend has a key, secret, spendable and spans"
    )]
    pub(super) fn check_spends(
        spend_rows: Vec<(action::Descriptor, ActionEntropy, value::Trapdoor)>,
        spend_pcds: Vec<(
            ProofAuthorizingKey,
            ragu::Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
            ragu::Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
            Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
        )>,
        anchor: Anchor,
    ) -> Result<Vec<SpendInput>, Box<dyn error::Error + Send + Sync>> {
        if spend_rows.len() != spend_pcds.len() {
            return Err(format!(
                "cannot prove {} spend actions with {} spendbind inputs",
                spend_rows.len(),
                spend_pcds.len(),
            )
            .into());
        }
        spend_rows
            .into_iter()
            .zip(spend_pcds)
            .enumerate()
            .map(
                |(index, ((descriptor, theta, rcv), (pak, secret, spendable, spans)))| {
                    let reached = spans
                        .last()
                        .map_or_else(|| spendable.data().2, |last| last.data().1);
                    if reached != anchor {
                        return Err(
                            format!("spend {index} does not reach the plan's anchor").into()
                        );
                    }
                    Ok(SpendInput {
                        descriptor,
                        theta,
                        rcv,
                        pak,
                        secret,
                        spendable,
                        spans,
                    })
                },
            )
            .collect()
    }

    pub(super) fn prove_actions<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        spend_inputs: Vec<SpendInput>,
        outputs: Vec<(action::Descriptor, ActionEntropy, Note, value::Trapdoor)>,
        anchor: Anchor,
    ) -> Result<Option<ProvedActions>, ragu::Error> {
        let mut entries = Vec::with_capacity(spend_inputs.len() + outputs.len());
        for input in spend_inputs {
            let SpendInput {
                descriptor,
                theta,
                rcv,
                pak,
                secret,
                spendable,
                spans,
            } = input;
            // SpendBind: derive the live pair from the note's master key and
            // commit the note's value.
            let (bind_pcd, ()) = app.fuse(
                rng,
                spend::SpendBind,
                witness::spend_bind((*spendable.data(), *secret.data()), rcv),
                spendable,
                secret,
            )?;

            let (digests, tachygrams, spend_anchor, proof, pair) =
                ProofStamp::prove_spend(rng, app, theta, bind_pcd, pak)?;
            entries.push(ProvedActions {
                proof: ActionsProof {
                    pairs: BTreeMap::from([(descriptor, pair)]),
                    anchor: spend_anchor,
                    proof,
                }
                .fuse_lift(rng, app, spans)?,
                sets: ActionSets {
                    digests,
                    tachygrams,
                },
            });
        }

        for (desc, theta, note, rcv) in outputs {
            let (digests, tachygrams, output_anchor, proof, pair) =
                ProofStamp::prove_output(rng, app, theta, rcv, note, anchor)?;
            entries.push(ProvedActions {
                proof: ActionsProof {
                    pairs: BTreeMap::from([(desc, pair)]),
                    anchor: output_anchor,
                    proof,
                },
                sets: ActionSets {
                    digests,
                    tachygrams,
                },
            });
        }

        let mut proofs = entries.into_iter();
        let Some(first) = proofs.next() else {
            return Ok(None);
        };
        proofs
            .try_fold(first, |left, right| {
                let sets = ActionSets {
                    digests: left
                        .sets
                        .digests
                        .union(&right.sets.digests)
                        .copied()
                        .collect(),
                    tachygrams: left
                        .sets
                        .tachygrams
                        .union(&right.sets.tachygrams)
                        .copied()
                        .collect(),
                };
                let proof = left.proof.fuse_merge(rng, app, right.proof, &sets)?;
                Ok(ProvedActions { proof, sets })
            })
            .map(Some)
    }
}

impl ActionSets {
    fn from_pairs<'pairs>(
        pairs: impl Iterator<Item = (&'pairs action::Descriptor, &'pairs (Tachygram, Tachygram))>,
    ) -> Self {
        let mut digests = BTreeSet::new();
        let mut tachygrams = BTreeSet::new();
        for (desc, &pair) in pairs {
            digests.insert(desc.digest(pair));
            tachygrams.extend(<[Tachygram; 2]>::from(pair));
        }
        Self {
            digests,
            tachygrams,
        }
    }
}

/// Rerandomized actions before a fee is applied.
#[derive(Clone, Debug)]
pub struct ActionsProof {
    /// The covered descriptors and their ordered tachygram pairs.
    pub pairs: BTreeMap<action::Descriptor, (Tachygram, Tachygram)>,
    /// The anchor at which the actions are proven.
    pub anchor: Anchor,
    /// The proof commits to the action and tachygram sets.
    #[debug(skip)]
    pub proof: Box<Uncompressed>,
}

impl ActionsProof {
    /// Advance the anchor along spans without changing the pairs. Each span
    /// must contain the anchor reached so far.
    ///
    /// # Errors
    ///
    /// Returns [`ragu::Error`] if Ragu cannot construct the proof.
    pub fn lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        spans: Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Result<Self, ragu::Error> {
        if spans.is_empty() {
            return Ok(self);
        }
        self.fuse_lift(rng, app, spans)?.rerandomize(rng, app)
    }

    fn fuse_lift<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        spans: Vec<ragu::Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Result<Self, ragu::Error> {
        let mut pcd = self.proof.carry::<Actions>(self.anchor);
        for span in spans {
            (pcd, ()) = app.fuse(rng, ActionLift, (), pcd, span)?;
        }
        let (proof, anchor) = pcd.into_parts();
        Ok(Self {
            pairs: self.pairs,
            anchor,
            proof: Box::new(proof),
        })
    }

    /// Merge and rerandomize proofs of disjoint actions at a common anchor.
    ///
    /// # Errors
    ///
    /// Returns [`MergeError`] if the anchors differ, descriptors overlap,
    /// or Ragu cannot construct the proof.
    ///
    /// # Panics
    ///
    /// Panics when digesting a descriptor with an identity `cv` or `rk`.
    pub fn merge<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        right: Self,
    ) -> Result<Self, MergeError> {
        if self.anchor != right.anchor {
            return Err(MergeError::AnchorMismatch);
        }
        if right.pairs.keys().any(|desc| self.pairs.contains_key(desc)) {
            return Err(MergeError::OverlappingActions);
        }
        let sets = ActionSets::from_pairs(self.pairs.iter().chain(&right.pairs));
        self.fuse_merge(rng, app, right, &sets)
            .and_then(|proof| proof.rerandomize(rng, app))
            .map_err(MergeError::ProofFailed)
    }

    fn fuse_merge<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        right: Self,
        sets: &ActionSets,
    ) -> Result<Self, ragu::Error> {
        let (pcd, ()) = app.fuse(
            rng,
            ActionMerge,
            witness::action_merge(
                (self.anchor, right.anchor),
                sets.digests.iter().copied().collect(),
                sets.tachygrams.iter().copied().collect(),
            ),
            self.proof.carry::<Actions>(self.anchor),
            right.proof.carry::<Actions>(right.anchor),
        )?;
        let (proof, anchor) = pcd.into_parts();
        Ok(Self {
            pairs: self.pairs.into_iter().chain(right.pairs).collect(),
            anchor,
            proof: Box::new(proof),
        })
    }

    fn rerandomize<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
    ) -> Result<Self, ragu::Error> {
        let (proof, anchor) = app
            .rerandomize(self.proof.carry::<Actions>(self.anchor), rng)?
            .into_parts();
        Ok(Self {
            pairs: self.pairs,
            anchor,
            proof: Box::new(proof),
        })
    }

    /// Apply the fee and rerandomize the stamp. Keep a copy of the actions
    /// proof to change the fee without proving the actions again.
    ///
    /// # Errors
    ///
    /// Returns [`FeeError`] if the max fee note's `rcm` is zero, the fee
    /// exceeds its value, or Ragu cannot construct the proof.
    ///
    /// # Panics
    ///
    /// Panics when digesting a descriptor with an identity `cv` or `rk`.
    pub fn fee<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        max_fee_note: Note,
        fee: value::Positive,
    ) -> Result<AutonomeParts, FeeError> {
        if Fp::from(max_fee_note.rcm) == Fp::ZERO {
            return Err(FeeError::ZeroRcm);
        }
        let value = value::Positive::try_from(i128::from(max_fee_note.value) - i128::from(fee))
            .map_err(|_err| FeeError::FeeAboveMax)?;
        let cm_change = Tachygram::from(
            Note {
                value,
                ..max_fee_note
            }
            .commitment(),
        );
        let sets = ActionSets::from_pairs(self.pairs.iter());
        self.fuse_fee(rng, app, max_fee_note, fee, cm_change, &sets)
            .map_err(FeeError::ProofFailed)
    }

    pub(super) fn fuse_fee<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        max_fee_note: Note,
        fee: value::Positive,
        cm_change: Tachygram,
        sets: &ActionSets,
    ) -> Result<AutonomeParts, ragu::Error> {
        let (fee_note, v_fee, (action_poly, tachygram_poly)) = witness::fee_fuse(
            (self.anchor, ()),
            max_fee_note,
            fee,
            &sets.digests,
            &sets.tachygrams,
        );
        let tachygram_set = tachygram_poly.commit();
        let (pcd, ()) = app.fuse(
            rng,
            FeeFuse,
            (fee_note, v_fee, (action_poly, tachygram_poly)),
            self.proof.carry::<Actions>(self.anchor),
            app.bootstrap_proof().clone().carry::<()>(()),
        )?;
        let stamp = AutonomeParts::finish(rng, app, pcd, tachygram_set)?;
        Ok(AutonomeParts {
            stamp,
            pairs: self.pairs,
            fee,
            cm_change,
        })
    }
}

/// A stamp and the bundle authorization data that it binds.
#[derive(Clone, Debug)]
pub struct AutonomeParts {
    /// The stamp, with no adjuncts.
    pub stamp: ProofStamp<Uncompressed>,
    /// The covered descriptors and their ordered tachygram pairs.
    pub pairs: BTreeMap<action::Descriptor, (Tachygram, Tachygram)>,
    /// The actual fee, not the maximum.
    pub fee: value::Positive,
    /// The fee change note commitment.
    pub cm_change: Tachygram,
}

impl AutonomeParts {
    /// Prove a stamp for a bundle with no actions and no fee.
    ///
    /// # Errors
    ///
    /// Returns [`SeedError`] if the max fee note's `rcm` or value is invalid,
    /// or Ragu cannot construct the proof.
    pub fn seed<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        max_fee_note: Note,
        anchor: Anchor,
    ) -> Result<Self, SeedError> {
        if Fp::from(max_fee_note.rcm) == Fp::ZERO {
            return Err(SeedError::ZeroRcm);
        }
        if max_fee_note.value != value::Positive::ZERO {
            return Err(SeedError::NonzeroMaxFee);
        }
        let stamp =
            Self::seed_stamp(rng, app, max_fee_note, anchor).map_err(SeedError::ProofFailed)?;
        Ok(Self {
            stamp,
            pairs: BTreeMap::new(),
            fee: value::Positive::ZERO,
            cm_change: max_fee_note.commitment().into(),
        })
    }

    pub(super) fn seed_stamp<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        max_fee_note: Note,
        anchor: Anchor,
    ) -> Result<ProofStamp<Uncompressed>, ragu::Error> {
        let (fee_note, seed_anchor, action_poly, tachygram_poly) =
            witness::fee_seed(((), ()), max_fee_note, anchor);
        let tachygram_set = tachygram_poly.commit();
        let (pcd, ()) = app.seed(
            rng,
            FeeSeed,
            (fee_note, seed_anchor, action_poly, tachygram_poly),
        )?;
        Self::finish(rng, app, pcd, tachygram_set)
    }

    fn finish<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        pcd: ragu::Pcd<Pasta, ProductionRank, Stamp>,
        tachygram_set: TachygramSetCommit,
    ) -> Result<ProofStamp<Uncompressed>, ragu::Error> {
        let (proof, (_, anchor)) = app.rerandomize(pcd, rng)?.into_parts();
        Ok(ProofStamp {
            anchor,
            tachygram_set,
            adjuncts: BTreeSet::new(),
            proof: Box::new(proof),
        })
    }
}

/// Errors while proving planned actions.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ActionsProveError {
    /// The plan contains no actions.
    #[display("no actions to prove")]
    NoActions,
    /// Missing PCD inputs for the operation.
    #[display("missing pcd inputs: {_0}")]
    MissingPcd(Box<dyn error::Error + Send + Sync + 'static>),
    /// An output note has a zero commitment trapdoor.
    #[display("zero output note commitment trapdoor")]
    ZeroRcm,
    /// Two actions share the same descriptor.
    #[display("duplicate action descriptor")]
    DuplicateAction,
    /// Proof construction failed; carries the underlying Ragu error.
    #[display("proof failed: {_0}")]
    ProofFailed(ragu::Error),
}

/// Errors while merging proofs of actions.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum MergeError {
    /// The proofs are at different anchors.
    #[display("action proofs have different anchors")]
    AnchorMismatch,
    /// Both proofs cover the same descriptor.
    #[display("action proofs overlap")]
    OverlappingActions,
    /// Ragu cannot construct the proof.
    #[display("proof failed: {_0}")]
    ProofFailed(ragu::Error),
}

/// Errors while applying a fee to proven actions.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum FeeError {
    /// The max fee note has a zero commitment trapdoor.
    #[display("zero max fee note commitment trapdoor")]
    ZeroRcm,
    /// The fee exceeds the max fee note's value.
    #[display("fee exceeds maximum")]
    FeeAboveMax,
    /// Ragu cannot construct the proof.
    #[display("proof failed: {_0}")]
    ProofFailed(ragu::Error),
}

/// Errors while proving a stamp without actions.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum SeedError {
    /// The max fee note has a zero commitment trapdoor.
    #[display("zero max fee note commitment trapdoor")]
    ZeroRcm,
    /// The max fee note has a nonzero value.
    #[display("nonzero maximum fee without actions")]
    NonzeroMaxFee,
    /// Ragu cannot construct the proof.
    #[display("proof failed: {_0}")]
    ProofFailed(ragu::Error),
}
