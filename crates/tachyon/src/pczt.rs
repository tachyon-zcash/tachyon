//! The Tachyon section of a partially constructed transaction.

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use ragu::{Pcd, ProductionRank, pasta::Pasta};

use crate::{
    Anchor, action,
    entropy::ActionEntropy,
    keys::{PaymentKey, ProofAuthorizingKey, SpendValidatingKey, private},
    note, nullifier,
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

impl Bundle {
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
