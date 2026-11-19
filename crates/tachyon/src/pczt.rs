//! The Tachyon section of a partially constructed transaction.

pub mod mirror;
#[cfg(test)]
mod tests;

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};

use derive_more::{Debug, Display, Eq as TotalEq, Error, PartialEq};
use ragu::{Pcd, ProductionRank, Rank as _, pasta::Pasta};
use udon::{curve::Affine as _, field::Field as _};

use crate::{
    Anchor, CompactSize, Note, action,
    digest::blake2b,
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{PaymentKey, ProofAuthorizingKey, SpendValidatingKey, private, public},
    note, nullifier,
    pasta::{EpAffine, Fp},
    primitives::{Effect, effect},
    stamp::{
        self,
        proof::{delegation, pool, spendable},
    },
    value,
};

/// A section with a fixed list of actions in commitment order.
#[derive(Clone, Debug)]
pub struct Bundle {
    actions: Vec<Action>,
    value_balance: value::Balance,
    max_fee: MaxFee,
    memo: Vec<u8>,
    anchor: Option<Anchor>,
    actions_proofs: Vec<stamp::ActionsProof>,
    autonome_parts: Option<stamp::AutonomeParts>,
    bsk: Option<private::BindingSigningKey>,
    #[debug(skip)]
    proprietary: BTreeMap<String, Vec<u8>>,
}

/// An action's immutable descriptor and its optional fields.
#[derive(Clone, Debug)]
pub struct Action {
    descriptor: action::Descriptor,
    sig: Option<action::Signature>,
    note: NoteOpening,
    theta: Option<ActionEntropy>,
    rcv: Option<value::Trapdoor>,
    witness: Option<ActionWitness>,
    #[debug(skip)]
    proprietary: BTreeMap<String, Vec<u8>>,
}

/// Independently redactable note fields.
#[derive(Clone, Copy, Debug)]
#[debug("NoteOpening(..)")]
pub struct NoteOpening {
    pk: Option<PaymentKey>,
    value: Option<value::Positive>,
    psi: Option<nullifier::Trapdoor>,
    rcm: Option<note::CommitmentTrapdoor>,
}

/// Information specific to one action kind.
#[derive(Clone, Debug)]
pub enum ActionWitness {
    /// A spend.
    Spend(SpendWitness),
    /// An output.
    Output(OutputWitness),
}

/// Spend authority, delegated proving data and signer metadata.
#[derive(Clone, Debug)]
pub struct SpendWitness {
    ak: Option<SpendValidatingKey>,
    pak: Option<Box<ProofAuthorizingKey>>,
    lineage: Option<SpendLineage>,
    zip32_derivation: Option<Zip32Derivation>,
}

/// The predecessor proofs used by a spend.
#[derive(Clone, Debug)]
#[debug("SpendLineage(..)")]
pub struct SpendLineage {
    secret: Box<Pcd<Pasta, ProductionRank, delegation::NoteSecret>>,
    spendable: Box<Pcd<Pasta, ProductionRank, spendable::NoteSpendable>>,
    spans: Vec<Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
}

/// Hints for reviewing an output.
#[derive(Clone, Debug)]
pub struct OutputWitness {
    zip32_derivation: Option<Zip32Derivation>,
    #[debug(skip)]
    user_address: Option<String>,
}

/// Hint for locating a key; not part of the effects.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("Zip32Derivation(..)")]
pub struct Zip32Derivation {
    seed_fingerprint: [u8; 32],
    derivation_path: Vec<u32>,
}

/// The committed maximum fee and its optional opening and metadata.
#[derive(Clone, Debug)]
pub struct MaxFee {
    cv_feemax: value::Commitment,
    note: NoteOpening,
    zip32_derivation: Option<Zip32Derivation>,
    #[debug(skip)]
    proprietary: BTreeMap<String, Vec<u8>>,
}

/// An opening is incomplete or fails to reproduce the effects.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum VerifyError {
    /// A needed field is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] OpeningField),
    /// The opening cannot produce the stored effects.
    #[display("action descriptor mismatch")]
    DescriptorMismatch,
    /// The note commitment trapdoor is zero.
    #[display("zero note commitment trapdoor")]
    ZeroRcm,
    /// The action randomness exceeds the circuit field's capacity.
    #[display("unrepresentable action randomness")]
    UnrepresentableActionRandomness,
}

enum DescriptorError {
    Missing(OpeningField),
    ZeroRcm,
    Randomness,
}

trait OpeningEffect: Effect {
    type Authority: Copy;
    fn verification_key(
        authority: Self::Authority,
        alpha: &ActionRandomizer<Self>,
    ) -> public::ActionVerificationKey;
}

impl OpeningEffect for effect::Spend {
    type Authority = SpendValidatingKey;

    fn verification_key(
        authority: Self::Authority,
        alpha: &ActionRandomizer<Self>,
    ) -> public::ActionVerificationKey {
        authority.derive_action_public(alpha)
    }
}

impl OpeningEffect for effect::Output {
    type Authority = ();

    fn verification_key(
        _authority: (),
        alpha: &ActionRandomizer<Self>,
    ) -> public::ActionVerificationKey {
        private::ActionSigningKey::new(alpha).derive_action_public()
    }
}

#[derive(Clone, Copy)]
struct Opening<E: OpeningEffect> {
    note: Note,
    theta: ActionEntropy,
    rcv: value::Trapdoor,
    authority: E::Authority,
}

#[derive(Clone, Copy)]
struct CheckedOpening<E: OpeningEffect> {
    opening: Opening<E>,
    descriptor: action::Descriptor,
}

enum OpeningCheckError {
    ZeroRcm,
    Randomness,
}

impl<E: OpeningEffect> Opening<E> {
    fn check(self) -> Result<CheckedOpening<E>, OpeningCheckError> {
        if Fp::from(self.note.rcm) == Fp::ZERO {
            return Err(OpeningCheckError::ZeroRcm);
        }
        let alpha = self.theta.randomizer::<E>(self.note.commitment());
        if !alpha.fits_base_field_capacity() || !self.rcv.fits_base_field_capacity() {
            return Err(OpeningCheckError::Randomness);
        }
        let descriptor = action::Descriptor {
            cv: E::commit_value(self.rcv, self.note.value),
            rk: E::verification_key(self.authority, &alpha),
        };
        Ok(CheckedOpening {
            opening: self,
            descriptor,
        })
    }
}

/// Checked preimages of the committed section.
#[derive(Clone, Debug)]
#[debug("Plan(..)")]
pub struct Plan {
    spends: Vec<CheckedOpening<effect::Spend>>,
    outputs: Vec<CheckedOpening<effect::Output>>,
    max_fee_note: Note,
    effects: Effects,
}

fn max_actions() -> usize {
    (ProductionRank::num_coeffs() - 2).div_euclid(2)
}

fn memo_fits(len: usize) -> bool {
    u64::try_from(len).is_ok_and(|size| CompactSize::from(size).enforce_valid().is_ok())
}

/// The plan's effecting data in commitment order.
#[derive(Clone, Debug)]
pub struct Effects {
    /// Action descriptors in commitment order.
    pub actions: Vec<action::Descriptor>,
    /// The signed net value.
    pub value_balance: value::Balance,
    /// The commitment to the maximum fee.
    pub cv_feemax: value::Commitment,
    /// The committed memo bytes.
    pub memo: Vec<u8>,
}

impl Effects {
    /// Compute the bundle's sighash contribution.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let descriptors: Vec<[u8; 64]> = self.actions.iter().copied().collect();
        blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&descriptors),
            self.value_balance.into(),
            &self.cv_feemax.into(),
            &blake2b::memo_digest(&self.memo),
        )
    }
}

/// A preimage cannot be used to construct a checked plan.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum PlanError {
    /// A note commitment trapdoor is zero.
    #[display("zero note commitment trapdoor")]
    ZeroRcm,
    /// Action randomness is not representable.
    #[display("unrepresentable action randomness")]
    UnrepresentableActionRandomness,
    /// The maximum fee blind is not representable.
    #[display("unrepresentable maximum fee blind")]
    UnrepresentableFeeBlind,
    /// The section has too many actions.
    #[display("too many actions")]
    TooManyActions,
    /// The memo exceeds the bundle encoding limit.
    #[display("memo exceeds the bundle encoding limit")]
    MemoTooLong,
    /// The signed balance is out of range.
    #[display("value balance out of range")]
    BalanceOverflow,
    /// Two actions have the same descriptor.
    #[display("duplicate action descriptor")]
    DuplicateAction,
    /// An effect contains the identity point.
    #[display("identity effect")]
    IdentityPoint,
    /// A section without actions has a nonzero maximum fee.
    #[display("nonzero maximum fee without actions")]
    FeeWithoutActions,
}

impl From<OpeningCheckError> for PlanError {
    fn from(error: OpeningCheckError) -> Self {
        match error {
            OpeningCheckError::ZeroRcm => Self::ZeroRcm,
            OpeningCheckError::Randomness => Self::UnrepresentableActionRandomness,
        }
    }
}

enum CheckedPlanError {
    ZeroRcm,
    UnrepresentableFeeBlind,
    BalanceOverflow,
    DuplicateAction,
    IdentityPoint,
    FeeWithoutActions,
}

impl From<CheckedPlanError> for PlanError {
    fn from(error: CheckedPlanError) -> Self {
        match error {
            CheckedPlanError::ZeroRcm => Self::ZeroRcm,
            CheckedPlanError::UnrepresentableFeeBlind => Self::UnrepresentableFeeBlind,
            CheckedPlanError::BalanceOverflow => Self::BalanceOverflow,
            CheckedPlanError::DuplicateAction => Self::DuplicateAction,
            CheckedPlanError::IdentityPoint => Self::IdentityPoint,
            CheckedPlanError::FeeWithoutActions => Self::FeeWithoutActions,
        }
    }
}

impl Plan {
    /// Construct a plan from spend and output preimages.
    ///
    /// # Errors
    ///
    /// Returns an error if the preimages cannot form a valid plan.
    pub fn new(
        spends: Vec<(Note, ActionEntropy, value::Trapdoor, SpendValidatingKey)>,
        outputs: Vec<(Note, ActionEntropy, value::Trapdoor)>,
        max_fee_note: Note,
        memo: Vec<u8>,
    ) -> Result<Self, PlanError> {
        if spends.len().saturating_add(outputs.len()) > max_actions() {
            return Err(PlanError::TooManyActions);
        }
        if !memo_fits(memo.len()) {
            return Err(PlanError::MemoTooLong);
        }
        let checked_spends = spends
            .into_iter()
            .map(|(note, theta, rcv, authority)| {
                Opening::<effect::Spend> {
                    note,
                    theta,
                    rcv,
                    authority,
                }
                .check()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let checked_outputs = outputs
            .into_iter()
            .map(|(note, theta, rcv)| {
                Opening::<effect::Output> {
                    note,
                    theta,
                    rcv,
                    authority: (),
                }
                .check()
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_checked(checked_spends, checked_outputs, max_fee_note, memo)
            .map_err(PlanError::from)
    }

    fn from_checked(
        spends: Vec<CheckedOpening<effect::Spend>>,
        outputs: Vec<CheckedOpening<effect::Output>>,
        max_fee_note: Note,
        memo: Vec<u8>,
    ) -> Result<Self, CheckedPlanError> {
        if spends.is_empty() && outputs.is_empty() && max_fee_note.value != value::Positive::ZERO {
            return Err(CheckedPlanError::FeeWithoutActions);
        }
        if Fp::from(max_fee_note.rcm) == Fp::ZERO {
            return Err(CheckedPlanError::ZeroRcm);
        }
        if !max_fee_note
            .derive_feemax_blind()
            .fits_base_field_capacity()
        {
            return Err(CheckedPlanError::UnrepresentableFeeBlind);
        }
        let balance = spends
            .iter()
            .map(|entry| i128::from(entry.opening.note.value))
            .sum::<i128>()
            - outputs
                .iter()
                .map(|entry| i128::from(entry.opening.note.value))
                .sum::<i128>()
            - i128::from(max_fee_note.value);
        let value_balance =
            value::Balance::try_from(balance).map_err(|_err| CheckedPlanError::BalanceOverflow)?;
        let cv_feemax = max_fee_note.cv_feemax();
        let mut actions = spends
            .iter()
            .map(|entry| entry.descriptor)
            .chain(outputs.iter().map(|entry| entry.descriptor))
            .collect::<Vec<action::Descriptor>>();
        if EpAffine::from(cv_feemax).is_identity()
            || actions.iter().any(|descriptor| {
                EpAffine::from(descriptor.cv).is_identity()
                    || EpAffine::from(descriptor.rk).is_identity()
            })
        {
            return Err(CheckedPlanError::IdentityPoint);
        }
        actions.sort_unstable();
        if actions
            .iter()
            .zip(actions.iter().skip(1))
            .any(|(left, right)| left == right)
        {
            return Err(CheckedPlanError::DuplicateAction);
        }
        Ok(Self {
            spends,
            outputs,
            max_fee_note,
            effects: Effects {
                actions,
                value_balance,
                cv_feemax,
                memo,
            },
        })
    }

    /// View the commitment data derived from the checked preimages.
    #[must_use]
    pub const fn effects(&self) -> &Effects {
        &self.effects
    }
}

/// An input to a PCZT opening.
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
pub enum OpeningField {
    /// Action kind.
    Witness,
    /// Spend validating key.
    Ak,
    /// An opening field of the note.
    #[display("note {_0}")]
    Note(NoteField),
    /// Action entropy.
    Theta,
    /// Value commitment trapdoor.
    Rcv,
}

/// A field of a note opening.
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
pub enum NoteField {
    /// Payment key.
    Pk,
    /// Note value.
    Value,
    /// Nullifier trapdoor.
    Psi,
    /// Note commitment trapdoor.
    Rcm,
}

/// A missing input and its position in the section.
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
#[expect(
    variant_size_differences,
    reason = "only indexed action fields carry a position"
)]
pub enum ReviewField {
    /// A field of the indexed action.
    #[display("action {_0} {_1}")]
    Action(usize, OpeningField),
    /// A field of the max fee opening.
    #[display("max fee {_0}")]
    MaxFee(NoteField),
}

/// An effect that does not match the derived plan.
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
pub enum ReviewEffect {
    /// Bundle balance.
    ValueBalance,
    /// Maximum fee commitment.
    MaxFee,
    /// Descriptor of the indexed action.
    Action(usize),
}

/// Failure to reconstruct the reviewed plan.
#[derive(Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum ReviewError {
    /// An opening is incomplete.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] ReviewField),
    /// Plan construction failed.
    #[display("invalid reviewed plan")]
    Plan(PlanError),
    /// A reconstructed effect differs from the section.
    #[display("effect mismatch: {_0}")]
    EffectsMismatch(#[error(not(source))] ReviewEffect),
}

impl Bundle {
    fn sort_actions_proofs(proofs: &mut [stamp::ActionsProof]) {
        proofs.sort_unstable_by_key(|proof| proof.pairs.keys().next().copied());
    }

    /// Open the section from a complete plan, without role contributions.
    #[must_use]
    pub fn from_plan(plan: &Plan) -> Self {
        let mut actions = plan
            .spends
            .iter()
            .copied()
            .map(|opening| {
                Action::from_opening(
                    opening,
                    ActionWitness::Spend(SpendWitness {
                        ak: Some(opening.opening.authority),
                        pak: None,
                        lineage: None,
                        zip32_derivation: None,
                    }),
                )
            })
            .chain(plan.outputs.iter().copied().map(|opening| {
                Action::from_opening(
                    opening,
                    ActionWitness::Output(OutputWitness {
                        zip32_derivation: None,
                        user_address: None,
                    }),
                )
            }))
            .collect::<Vec<_>>();
        actions.sort_unstable_by_key(|action| action.descriptor);
        Self {
            actions,
            value_balance: plan.effects.value_balance,
            max_fee: MaxFee {
                cv_feemax: plan.effects.cv_feemax,
                note: NoteOpening::from_note(plan.max_fee_note),
                zip32_derivation: None,
                proprietary: BTreeMap::new(),
            },
            memo: plan.effects.memo.clone(),
            anchor: None,
            actions_proofs: Vec::new(),
            autonome_parts: None,
            bsk: None,
            proprietary: BTreeMap::new(),
        }
    }

    /// The stored effects, which need not have openings.
    #[must_use]
    pub fn effects(&self) -> Effects {
        Effects {
            value_balance: self.value_balance,
            actions: self
                .actions
                .iter()
                .map(|action| action.descriptor)
                .collect(),
            cv_feemax: self.max_fee.cv_feemax,
            memo: self.memo.clone(),
        }
    }

    /// Derive a complete plan and compare its effects with the section's.
    ///
    /// # Errors
    ///
    /// Returns an error if an opening is missing or inconsistent.
    #[expect(clippy::ref_patterns, reason = "borrow the spend opening")]
    pub fn plan(&self) -> Result<Plan, ReviewError> {
        let mut spends = Vec::new();
        let mut outputs = Vec::new();
        for (index, action) in self.actions.iter().enumerate() {
            let missing = |field| ReviewError::Missing(ReviewField::Action(index, field));
            match *action
                .witness
                .as_ref()
                .ok_or_else(|| missing(OpeningField::Witness))?
            {
                ActionWitness::Spend(ref spend) => {
                    let ak = spend.ak.ok_or_else(|| missing(OpeningField::Ak))?;
                    let opening = action
                        .opening::<effect::Spend>(ak)
                        .map_err(missing)?
                        .check()
                        .map_err(|err| ReviewError::Plan(err.into()))?;
                    if action.descriptor != opening.descriptor {
                        return Err(ReviewError::EffectsMismatch(ReviewEffect::Action(index)));
                    }
                    spends.push(opening);
                },
                ActionWitness::Output(_) => {
                    let opening = action
                        .opening::<effect::Output>(())
                        .map_err(missing)?
                        .check()
                        .map_err(|err| ReviewError::Plan(err.into()))?;
                    if action.descriptor != opening.descriptor {
                        return Err(ReviewError::EffectsMismatch(ReviewEffect::Action(index)));
                    }
                    outputs.push(opening);
                },
            }
        }
        let plan = Plan::from_checked(
            spends,
            outputs,
            self.max_fee
                .note
                .complete()
                .map_err(|field| ReviewError::Missing(ReviewField::MaxFee(field)))?,
            self.memo.clone(),
        )
        .map_err(|err| ReviewError::Plan(err.into()))?;
        let effects = &plan.effects;
        if self.value_balance != effects.value_balance {
            return Err(ReviewError::EffectsMismatch(ReviewEffect::ValueBalance));
        }
        if self.max_fee.cv_feemax != effects.cv_feemax {
            return Err(ReviewError::EffectsMismatch(ReviewEffect::MaxFee));
        }
        Ok(plan)
    }

    /// The actions in commitment order.
    #[must_use]
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// The net value balance.
    #[must_use]
    pub const fn value_balance(&self) -> value::Balance {
        self.value_balance
    }

    /// The bundle memo.
    #[must_use]
    pub fn memo(&self) -> &[u8] {
        &self.memo
    }

    /// The maximum fee.
    #[must_use]
    pub const fn max_fee(&self) -> &MaxFee {
        &self.max_fee
    }

    /// The optional proving target.
    #[must_use]
    pub const fn anchor(&self) -> Option<Anchor> {
        self.anchor
    }

    /// The disjoint pre-fee proofs.
    #[must_use]
    pub fn actions_proofs(&self) -> &[stamp::ActionsProof] {
        &self.actions_proofs
    }

    /// The fee-applied proof and its associated data.
    #[must_use]
    pub const fn autonome_parts(&self) -> Option<&stamp::AutonomeParts> {
        self.autonome_parts.as_ref()
    }

    /// The key computed by the IO Finalizer.
    #[must_use]
    pub const fn bsk(&self) -> Option<&private::BindingSigningKey> {
        self.bsk.as_ref()
    }

    /// Bundle metadata.
    #[must_use]
    pub const fn proprietary(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.proprietary
    }
}

impl Action {
    const fn from_opening<E: OpeningEffect>(
        checked: CheckedOpening<E>,
        witness: ActionWitness,
    ) -> Self {
        Self {
            descriptor: checked.descriptor,
            sig: None,
            note: NoteOpening::from_note(checked.opening.note),
            theta: Some(checked.opening.theta),
            rcv: Some(checked.opening.rcv),
            witness: Some(witness),
            proprietary: BTreeMap::new(),
        }
    }

    fn opening<E: OpeningEffect>(
        &self,
        authority: E::Authority,
    ) -> Result<Opening<E>, OpeningField> {
        Self::opening_from(&self.note, self.theta, self.rcv, authority)
    }

    fn opening_from<E: OpeningEffect>(
        note: &NoteOpening,
        theta: Option<ActionEntropy>,
        rcv: Option<value::Trapdoor>,
        authority: E::Authority,
    ) -> Result<Opening<E>, OpeningField> {
        Ok(Opening {
            note: note.complete().map_err(OpeningField::Note)?,
            theta: theta.ok_or(OpeningField::Theta)?,
            rcv: rcv.ok_or(OpeningField::Rcv)?,
            authority,
        })
    }

    /// Compare the derived descriptor with the stored descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or inconsistent opening.
    pub fn verify_opening(&self) -> Result<(), VerifyError> {
        if Self::derive_from_opening(&self.note, self.theta, self.rcv, self.witness.as_ref())
            .map_err(|error| match error {
                DescriptorError::Missing(field) => VerifyError::Missing(field),
                DescriptorError::ZeroRcm => VerifyError::ZeroRcm,
                DescriptorError::Randomness => VerifyError::UnrepresentableActionRandomness,
            })?
            != self.descriptor
        {
            return Err(VerifyError::DescriptorMismatch);
        }
        Ok(())
    }

    #[expect(clippy::ref_patterns, reason = "borrow the spend opening")]
    fn derive_from_opening(
        note: &NoteOpening,
        theta: Option<ActionEntropy>,
        rcv: Option<value::Trapdoor>,
        witness: Option<&ActionWitness>,
    ) -> Result<action::Descriptor, DescriptorError> {
        let derived = match *witness.ok_or(DescriptorError::Missing(OpeningField::Witness))? {
            ActionWitness::Spend(ref spend) => Self::opening_from::<effect::Spend>(
                note,
                theta,
                rcv,
                spend.ak.ok_or(DescriptorError::Missing(OpeningField::Ak))?,
            )
            .map_err(DescriptorError::Missing)?
            .check()
            .map(|checked| checked.descriptor),
            ActionWitness::Output(_) => Self::opening_from::<effect::Output>(note, theta, rcv, ())
                .map_err(DescriptorError::Missing)?
                .check()
                .map(|checked| checked.descriptor),
        };
        derived.map_err(|error| match error {
            OpeningCheckError::ZeroRcm => DescriptorError::ZeroRcm,
            OpeningCheckError::Randomness => DescriptorError::Randomness,
        })
    }

    /// The action's descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> action::Descriptor {
        self.descriptor
    }

    /// Its authorization signature, if present.
    #[must_use]
    pub const fn sig(&self) -> Option<action::Signature> {
        self.sig
    }

    /// The note's opening fields.
    #[must_use]
    pub const fn note(&self) -> &NoteOpening {
        &self.note
    }

    /// Its entropy.
    #[must_use]
    pub const fn theta(&self) -> Option<ActionEntropy> {
        self.theta
    }

    /// Its value commitment trapdoor.
    #[must_use]
    pub const fn rcv(&self) -> Option<value::Trapdoor> {
        self.rcv
    }

    /// Action-kind-specific data.
    #[must_use]
    pub const fn witness(&self) -> Option<&ActionWitness> {
        self.witness.as_ref()
    }

    /// Action metadata.
    #[must_use]
    pub const fn proprietary(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.proprietary
    }
}

impl NoteOpening {
    const fn from_note(note: Note) -> Self {
        Self {
            pk: Some(note.pk),
            value: Some(note.value),
            psi: Some(note.psi),
            rcm: Some(note.rcm),
        }
    }

    fn complete(&self) -> Result<Note, NoteField> {
        Ok(Note {
            pk: self.pk.ok_or(NoteField::Pk)?,
            value: self.value.ok_or(NoteField::Value)?,
            psi: self.psi.ok_or(NoteField::Psi)?,
            rcm: self.rcm.ok_or(NoteField::Rcm)?,
        })
    }

    /// The payment key.
    #[must_use]
    pub const fn pk(&self) -> Option<PaymentKey> {
        self.pk
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> Option<value::Positive> {
        self.value
    }

    /// The nullifier trapdoor.
    #[must_use]
    pub const fn psi(&self) -> Option<nullifier::Trapdoor> {
        self.psi
    }

    /// The note commitment trapdoor.
    #[must_use]
    pub const fn rcm(&self) -> Option<note::CommitmentTrapdoor> {
        self.rcm
    }
}

impl MaxFee {
    /// The commitment to the maximum fee.
    #[must_use]
    pub const fn cv_feemax(&self) -> value::Commitment {
        self.cv_feemax
    }

    /// The max fee note's opening fields.
    #[must_use]
    pub const fn note(&self) -> &NoteOpening {
        &self.note
    }

    /// The change recipient's key path.
    #[must_use]
    pub const fn zip32_derivation(&self) -> Option<&Zip32Derivation> {
        self.zip32_derivation.as_ref()
    }

    /// Max fee metadata.
    #[must_use]
    pub const fn proprietary(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.proprietary
    }
}

impl SpendWitness {
    fn keys_match(ak: Option<SpendValidatingKey>, pak: Option<ProofAuthorizingKey>) -> bool {
        ak.zip(pak).is_none_or(|(owner, delegate)| {
            <[u8; 32]>::from(owner.0) == <[u8; 32]>::from(delegate.ak.0)
        })
    }

    /// The spend's owner.
    #[must_use]
    pub const fn ak(&self) -> Option<SpendValidatingKey> {
        self.ak
    }

    /// The proving capability.
    #[must_use]
    pub fn pak(&self) -> Option<ProofAuthorizingKey> {
        self.pak.as_deref().copied()
    }

    /// The predecessor proofs.
    #[must_use]
    pub const fn lineage(&self) -> Option<&SpendLineage> {
        self.lineage.as_ref()
    }

    /// The owner's key path.
    #[must_use]
    pub const fn zip32_derivation(&self) -> Option<&Zip32Derivation> {
        self.zip32_derivation.as_ref()
    }
}

impl SpendLineage {
    /// Supply the predecessor proofs for a spend.
    #[must_use]
    pub fn new(
        secret: Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
        spendable: Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        spans: Vec<Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Self {
        Self {
            secret: Box::new(secret),
            spendable: Box::new(spendable),
            spans,
        }
    }

    /// The note secret.
    #[must_use]
    pub const fn secret(&self) -> &Pcd<Pasta, ProductionRank, delegation::NoteSecret> {
        &self.secret
    }

    /// The spendable proof.
    #[must_use]
    pub const fn spendable(&self) -> &Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        &self.spendable
    }

    /// The spans from the spendable anchor to the proving target.
    #[must_use]
    pub fn spans(&self) -> &[Pcd<Pasta, ProductionRank, pool::AnchorSpan>] {
        &self.spans
    }
}

impl OutputWitness {
    /// The recipient's key path.
    #[must_use]
    pub const fn zip32_derivation(&self) -> Option<&Zip32Derivation> {
        self.zip32_derivation.as_ref()
    }

    /// The address supplied for display, not authenticated by the effects.
    #[must_use]
    pub fn user_address(&self) -> Option<&str> {
        self.user_address.as_deref()
    }
}

impl Zip32Derivation {
    /// Supply a seed fingerprint and the raw child indices of a key path.
    #[must_use]
    pub const fn new(seed_fingerprint: [u8; 32], derivation_path: Vec<u32>) -> Self {
        Self {
            seed_fingerprint,
            derivation_path,
        }
    }

    /// The seed fingerprint.
    #[must_use]
    pub const fn seed_fingerprint(&self) -> [u8; 32] {
        self.seed_fingerprint
    }

    /// Child indices, including their hardened bits.
    #[must_use]
    pub fn derivation_path(&self) -> &[u32] {
        &self.derivation_path
    }
}
