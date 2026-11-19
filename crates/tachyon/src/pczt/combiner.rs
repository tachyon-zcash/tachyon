use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    string::String,
    vec::Vec,
};

use derive_more::{Display, Error};

use super::{
    Bundle, NoteField,
    mirror::{ActionWitness, CoverageReason, Field, NoteOpening, ParseError},
};

/// Two sections disagree or cannot be represented together.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum CombineError {
    /// Sections commit to different effects.
    #[display("effects mismatch")]
    EffectsMismatch,
    /// Two present values disagree.
    #[display("field conflict: {_0}")]
    FieldConflict(#[error(not(source))] ConflictField),
    /// Two different proof subsets intersect.
    #[display("overlapping action proofs")]
    ProofOverlap,
    /// The union violates a section invariant.
    #[display("invalid PCZT union")]
    InvalidUnion(ParseError),
}

/// The section member holding a conflicting value.
#[derive(Clone, Copy, Debug, Display)]
pub enum ConflictLocation {
    /// The bundle.
    Bundle,
    /// The maximum fee note.
    MaxFee,
    /// An indexed action.
    #[display("action {_0}")]
    Action(usize),
}

/// A conflicting contribution.
#[derive(Debug, Display)]
pub enum ConflictField {
    /// Proving anchor.
    Anchor,
    /// Binding signing key.
    Bsk,
    /// Fee-applied proof.
    AutonomeParts,
    /// Different proof bytes for identical action coverage.
    ActionsProof,
    /// A conflicting field in an action.
    #[display("action {_0} {_1}")]
    Action(usize, ActionConflictField),
    /// A conflicting field in the maximum fee opening.
    #[display("maximum fee note {_0}")]
    MaxFeeNote(NoteField),
    /// The fee change recipient's key path.
    #[display("maximum fee key path")]
    MaxFeeKeyPath,
    /// A proprietary map entry.
    #[display("{_0} proprietary entry {_1}")]
    Proprietary(ConflictLocation, String),
}

/// An action field that differs between two sections.
#[derive(Clone, Copy, Debug, Display)]
pub enum ActionConflictField {
    /// The action signature.
    Signature,
    /// The witness kind.
    Witness,
    /// The spend validating key.
    Ak,
    /// The proof authorizing key.
    Pak,
    /// The spend lineage.
    Lineage,
    /// The key path.
    KeyPath,
    /// The recipient display address.
    UserAddress,
    /// A field of the note opening.
    #[display("note {_0}")]
    Note(NoteField),
    /// The action entropy.
    Theta,
    /// The value commitment trapdoor.
    Rcv,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "the combiner is defined with its role"
)]
impl Bundle {
    /// Merge independent contributions to the same effects.
    ///
    /// # Errors
    ///
    /// Returns an error for unequal effects, conflicting fields, overlapping
    /// contributions or a union that violates a section invariant.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the role consumes both sections"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "combine checks all fields before parsing the union"
    )]
    pub fn combine(self, other: Self) -> Result<Self, CombineError> {
        if self.value_balance != other.value_balance
            || self.memo != other.memo
            || self.max_fee.cv_feemax != other.max_fee.cv_feemax
            || self
                .actions
                .iter()
                .map(|action| action.descriptor)
                .ne(other.actions.iter().map(|action| action.descriptor))
        {
            return Err(CombineError::EffectsMismatch);
        }
        // Compare canonical fields, including proof bytes, rather than only
        // comparing what the proofs attest to.
        let mut left = self.to_mirror();
        let right = other.to_mirror();
        Self::merge_field(&mut left.anchor, right.anchor, ConflictField::Anchor)?;
        Self::merge_field(&mut left.bsk, right.bsk, ConflictField::Bsk)?;
        Self::merge_field(
            &mut left.autonome_parts,
            right.autonome_parts,
            ConflictField::AutonomeParts,
        )?;
        Self::merge_map(&mut left.proprietary, right.proprietary)
            .map_err(|key| ConflictField::Proprietary(ConflictLocation::Bundle, key))?;
        left.max_fee
            .note
            .merge(right.max_fee.note, ConflictField::MaxFeeNote)?;
        Self::merge_field(
            &mut left.max_fee.zip32_derivation,
            right.max_fee.zip32_derivation,
            ConflictField::MaxFeeKeyPath,
        )?;
        Self::merge_map(&mut left.max_fee.proprietary, right.max_fee.proprietary)
            .map_err(|key| ConflictField::Proprietary(ConflictLocation::MaxFee, key))?;
        for (index, (action, contribution)) in
            left.actions.iter_mut().zip(right.actions).enumerate()
        {
            let loc = ConflictLocation::Action(index);
            let conflict = |field| ConflictField::Action(index, field);
            Self::merge_field(
                &mut action.sig,
                contribution.sig,
                conflict(ActionConflictField::Signature),
            )?;
            Self::merge_field(
                &mut action.theta,
                contribution.theta,
                conflict(ActionConflictField::Theta),
            )?;
            Self::merge_field(
                &mut action.rcv,
                contribution.rcv,
                conflict(ActionConflictField::Rcv),
            )?;
            action.note.merge(contribution.note, |note| {
                conflict(ActionConflictField::Note(note))
            })?;
            Self::merge_map(&mut action.proprietary, contribution.proprietary)
                .map_err(|key| ConflictField::Proprietary(loc, key))?;
            match (&mut action.witness, contribution.witness) {
                (
                    &mut Some(ActionWitness::Spend(ref mut spend)),
                    Some(ActionWitness::Spend(other_spend)),
                ) => {
                    Self::merge_field(
                        &mut spend.ak,
                        other_spend.ak,
                        conflict(ActionConflictField::Ak),
                    )?;
                    Self::merge_field(
                        &mut spend.pak,
                        other_spend.pak,
                        conflict(ActionConflictField::Pak),
                    )?;
                    Self::merge_field(
                        &mut spend.lineage,
                        other_spend.lineage,
                        conflict(ActionConflictField::Lineage),
                    )?;
                    Self::merge_field(
                        &mut spend.zip32_derivation,
                        other_spend.zip32_derivation,
                        conflict(ActionConflictField::KeyPath),
                    )?;
                },
                (
                    &mut Some(ActionWitness::Output(ref mut output)),
                    Some(ActionWitness::Output(other_output)),
                ) => {
                    Self::merge_field(
                        &mut output.zip32_derivation,
                        other_output.zip32_derivation,
                        conflict(ActionConflictField::KeyPath),
                    )?;
                    Self::merge_field(
                        &mut output.user_address,
                        other_output.user_address,
                        conflict(ActionConflictField::UserAddress),
                    )?;
                },
                (witness @ &mut None, new_witness) => *witness = new_witness,
                (&mut Some(_), None) => {},
                (&mut Some(ActionWitness::Spend(_)), Some(ActionWitness::Output(_)))
                | (&mut Some(ActionWitness::Output(_)), Some(ActionWitness::Spend(_))) => {
                    return Err(CombineError::FieldConflict(conflict(
                        ActionConflictField::Witness,
                    )));
                },
            }
        }
        // Equal proof fields include equal coverage. Parsing rejects any
        // coverage intersection between the remaining, distinct proofs.
        for proof in right.actions_proofs {
            if let Some(stored) = left.actions_proofs.iter().find(|stored| {
                stored
                    .pairs
                    .iter()
                    .map(|pair| pair.descriptor)
                    .eq(proof.pairs.iter().map(|pair| pair.descriptor))
            }) {
                if *stored != proof {
                    return Err(CombineError::FieldConflict(ConflictField::ActionsProof));
                }
            } else {
                left.actions_proofs.push(proof);
            }
        }
        Self::parse(left).map_err(|err| {
            // A disjoint nonempty proof consumes at least one action.
            if matches!(
                err,
                ParseError::InvalidCoverage(_, CoverageReason::Overlap)
                    | ParseError::Limit(Field::ActionsProofs)
            ) {
                CombineError::ProofOverlap
            } else {
                CombineError::InvalidUnion(err)
            }
        })
    }

    fn merge_field<T: Eq>(
        field: &mut Option<T>,
        contribution: Option<T>,
        name: ConflictField,
    ) -> Result<(), ConflictField> {
        if field.is_some() && contribution.is_some() && *field != contribution {
            return Err(name);
        }
        if field.is_none() {
            *field = contribution;
        }
        Ok(())
    }

    fn merge_map(
        map: &mut BTreeMap<String, Vec<u8>>,
        contribution: BTreeMap<String, Vec<u8>>,
    ) -> Result<(), String> {
        for (key, value) in contribution {
            match map.entry(key) {
                Entry::Occupied(entry) if *entry.get() != value => {
                    return Err(entry.key().clone());
                },
                Entry::Occupied(_) => {},
                Entry::Vacant(entry) => {
                    entry.insert(value);
                },
            }
        }
        Ok(())
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "merging and decoding are separate operations"
)]
impl NoteOpening {
    fn merge(
        &mut self,
        other: Self,
        field: impl Fn(NoteField) -> ConflictField,
    ) -> Result<(), ConflictField> {
        Bundle::merge_field(&mut self.pk, other.pk, field(NoteField::Pk))?;
        Bundle::merge_field(&mut self.value, other.value, field(NoteField::Value))?;
        Bundle::merge_field(&mut self.psi, other.psi, field(NoteField::Psi))?;
        Bundle::merge_field(&mut self.rcm, other.rcm, field(NoteField::Rcm))
    }
}

impl From<ConflictField> for CombineError {
    fn from(field: ConflictField) -> Self {
        Self::FieldConflict(field)
    }
}
