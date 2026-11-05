//! A partially created Tachyon bundle, for PCZT.
//!
//! A [`Bundle`] carries a Tachyon bundle through the PCZT roles. Each field a
//! role writes is optional, so copies can be passed between parties,
//! combined, and redacted. A role fills absent fields and never overwrites a
//! present one.
//!
//! - Constructor: [`Bundle::new`], [`Bundle::add_spend`],
//!   [`Bundle::add_output`].
//! - Effects: [`Bundle::finalize_effects`] by a planner, or
//!   [`Bundle::authorize`] by custody, fixes `theta` and `rcv` and derives
//!   `cv`, `rk` and `cv_fee_max`.
//! - Signer: [`Bundle::authorize`], [`Bundle::sign_outputs`],
//!   [`Bundle::sign_binding`].
//! - Prover: [`Bundle::prove_partial`], [`Bundle::merge_partials`],
//!   [`Bundle::stamp`], [`Bundle::seed_stamp`].
//! - Combiner: [`Bundle::combine`].
//! - Redactor: [`Bundle::redact`].
//! - Transaction Extractor: [`Bundle::extract`].
//!
//! The transaction sighash is computed outside this module and passed in.

mod combiner;
mod extractor;
mod prover;
mod signer;

use alloc::{collections::BTreeSet, vec::Vec};
use core::marker::PhantomData;

pub use combiner::CombineError;
use derive_more::{Debug, Display, Eq as TotalEq, PartialEq};
pub use extractor::ExtractError;
pub use prover::ProverError;
pub use signer::SignerError;

use crate::{
    action, bundle,
    entropy::ActionEntropy,
    keys::{PaymentKey, SpendValidatingKey, public},
    note::{self, Note},
    nullifier,
    primitives::{Effect, effect},
    stamp::{ActionsProof, ProofStamp},
    value,
};

/// Names an action or the max fee note of a [`Bundle`].
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
pub enum Slot {
    /// The spend at this index.
    #[display("spend {_0}")]
    Spend(usize),
    /// The output at this index.
    #[display("output {_0}")]
    Output(usize),
    /// The max fee note.
    #[display("max fee note")]
    MaxFee,
}

/// A note opening whose fields may be absent.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoteOpening {
    /// The owner's payment key.
    pub pk: Option<PaymentKey>,
    /// The note value.
    pub value: Option<value::Positive>,
    /// The nullifier trapdoor.
    pub psi: Option<nullifier::Trapdoor>,
    /// The note commitment trapdoor.
    pub rcm: Option<note::CommitmentTrapdoor>,
}

impl NoteOpening {
    /// The note, if every field is present.
    #[must_use]
    pub fn note(&self) -> Option<Note> {
        Some(Note {
            pk: self.pk?,
            value: self.value?,
            psi: self.psi?,
            rcm: self.rcm?,
        })
    }
}

impl From<Note> for NoteOpening {
    fn from(note: Note) -> Self {
        Self {
            pk: Some(note.pk),
            value: Some(note.value),
            psi: Some(note.psi),
            rcm: Some(note.rcm),
        }
    }
}

/// One action of a [`Bundle`].
#[derive(Clone, Debug)]
pub struct Action<E: Effect> {
    /// The note spent or created.
    pub note: NoteOpening,

    /// The spend validating key of the note's owner.
    ///
    /// A spend is signed by the custody holding this key. An absent owner
    /// is the custody that authorizes the bundle. An output or max fee note
    /// whose owner is the authorizing custody's key takes that custody's
    /// payment key.
    pub owner: Option<SpendValidatingKey>,

    /// Per-action entropy for alpha derivation.
    pub theta: Option<ActionEntropy>,

    /// Value commitment trapdoor.
    pub rcv: Option<value::Trapdoor>,

    /// Value commitment.
    pub cv: Option<value::Commitment>,

    /// Randomized action verification key.
    pub rk: Option<public::ActionVerificationKey>,

    /// Action signature over the transaction sighash.
    pub sig: Option<action::Signature>,

    /// Effect marker (zero-sized).
    #[debug(skip)]
    pub _effect: PhantomData<E>,
}

impl<E: Effect> Action<E> {
    const fn new(note: NoteOpening, owner: Option<SpendValidatingKey>) -> Self {
        Self {
            note,
            owner,
            theta: None,
            rcv: None,
            cv: None,
            rk: None,
            sig: None,
            _effect: PhantomData,
        }
    }

    /// Clear every field that is not published.
    const fn redact(&mut self) {
        self.note = NoteOpening {
            pk: None,
            value: None,
            psi: None,
            rcm: None,
        };
        self.owner = None;
        self.theta = None;
        self.rcv = None;
    }
}

/// Proven actions with no fee applied, and the bundle indices they cover.
#[derive(Clone, Debug)]
pub struct Partial {
    /// The covered spend indices.
    pub spends: BTreeSet<usize>,

    /// The covered output indices.
    pub outputs: BTreeSet<usize>,

    /// The proof of the covered actions.
    pub proof: ActionsProof,
}

impl Partial {
    /// Whether this partial covers every action `other` covers.
    fn covers(&self, other: &Self) -> bool {
        other.spends.is_subset(&self.spends) && other.outputs.is_subset(&self.outputs)
    }

    /// Whether this partial covers an action `other` covers.
    fn overlaps(&self, other: &Self) -> bool {
        !self.spends.is_disjoint(&other.spends) || !self.outputs.is_disjoint(&other.outputs)
    }
}

/// A partially created Tachyon bundle.
#[derive(Clone, Debug)]
pub struct Bundle {
    /// Spend actions.
    pub spends: Vec<Action<effect::Spend>>,

    /// Output actions.
    pub outputs: Vec<Action<effect::Output>>,

    /// Net value of spends minus outputs and max fee, kept by the
    /// Constructor.
    pub value_balance: value::Balance,

    /// The max fee note.
    pub max_fee_note: NoteOpening,

    /// The spend validating key of the max fee note's owner, as for an
    /// output's [`Action::owner`].
    pub max_fee_owner: Option<SpendValidatingKey>,

    /// The max fee note's value commitment.
    pub cv_fee_max: Option<value::Commitment>,

    /// Opaque recipient-directed payload, empty when absent.
    pub memo: Vec<u8>,

    /// Binding signature over the transaction sighash.
    pub binding_sig: Option<bundle::Signature>,

    /// Proven actions with no fee applied.
    pub partials: Vec<Partial>,

    /// The stamp, with the bundle's fee applied.
    pub stamp: Option<ProofStamp>,
}

#[expect(clippy::multiple_inherent_impl, reason = "one impl block per role")]
impl Bundle {
    /// Create a bundle with no actions, reserving `max_fee_note` and carrying
    /// `memo`.
    ///
    /// # Panics
    ///
    /// Panics if the max fee note has no value, `psi` or `rcm`, or if it has
    /// neither a payment key nor an owner.
    #[must_use]
    pub fn new(
        max_fee_note: NoteOpening,
        max_fee_owner: Option<SpendValidatingKey>,
        memo: Vec<u8>,
    ) -> Self {
        let max_fee = constructed_value(&max_fee_note, max_fee_owner.is_some(), "max fee note");

        Self {
            spends: Vec::new(),
            outputs: Vec::new(),
            value_balance: value::Balance::from(-max_fee),
            max_fee_note,
            max_fee_owner,
            cv_fee_max: None,
            memo,
            binding_sig: None,
            partials: Vec::new(),
            stamp: None,
        }
    }

    /// Add a spend of `note`, signed by the custody holding `owner`, and
    /// return its index.
    ///
    /// # Panics
    ///
    /// Panics if the value balance leaves its range.
    pub fn add_spend(&mut self, note: Note, owner: Option<SpendValidatingKey>) -> usize {
        self.adjust_balance(i128::from(note.value));
        self.spends
            .push(Action::new(NoteOpening::from(note), owner));
        self.spends.len() - 1
    }

    /// Add an output of `note` and return its index. An output whose `owner`
    /// is the authorizing custody's key may leave its payment key absent.
    ///
    /// # Panics
    ///
    /// Panics if the note has no value, `psi` or `rcm`, if it has neither a
    /// payment key nor an owner, or if the value balance leaves its range.
    pub fn add_output(&mut self, note: NoteOpening, owner: Option<SpendValidatingKey>) -> usize {
        let note_value = constructed_value(&note, owner.is_some(), "output");
        self.adjust_balance(-i128::from(note_value));
        self.outputs.push(Action::new(note, owner));
        self.outputs.len() - 1
    }

    /// Clear every field that is not published: note openings, owners,
    /// entropy, trapdoors and partial proofs.
    pub fn redact(&mut self) {
        self.spends.iter_mut().for_each(Action::redact);
        self.outputs.iter_mut().for_each(Action::redact);
        self.max_fee_note = NoteOpening::default();
        self.max_fee_owner = None;
        self.partials.clear();
    }

    #[expect(clippy::expect_used, reason = "builders reject invalid input")]
    fn adjust_balance(&mut self, delta: i128) {
        self.value_balance = value::Balance::try_from(i128::from(self.value_balance) + delta)
            .expect("value balance out of range");
    }
}

/// The value of a note added by the Constructor.
///
/// # Panics
///
/// Panics if the note has no value, `psi` or `rcm`, or if it has neither a
/// payment key nor an owner.
#[expect(clippy::expect_used, reason = "builders reject invalid input")]
fn constructed_value(note: &NoteOpening, owned: bool, kind: &str) -> value::Positive {
    assert!(
        note.psi.is_some() && note.rcm.is_some(),
        "{kind} needs psi and rcm"
    );
    assert!(
        note.pk.is_some() || owned,
        "{kind} needs a payment key or an owner"
    );
    note.value.expect("a constructed note needs a value")
}
