//! Effects and signatures.

use alloc::{collections::BTreeSet, vec::Vec};

use derive_more::{Display, Eq as TotalEq, Error, PartialEq};
use rand_core::CryptoRng;

use super::{Bundle, NoteOpening, Slot};
use crate::{
    action,
    digest::blake2b,
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{PaymentKey, ProofAuthorizingKey, SpendValidatingKey, private, public},
    primitives::{Effect as _, effect},
    value,
};

/// Errors from the effects and signer roles.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum SignerError {
    /// A note opening is incomplete.
    #[display("{_0} has an incomplete note")]
    MissingNote(#[error(not(source))] Slot),
    /// An action has no `theta` or `rcv`.
    #[display("{_0} has no theta or rcv")]
    MissingEntropy(#[error(not(source))] Slot),
    /// An action has no `cv` or `rk`, or the max fee note no `cv_feemax`.
    #[display("{_0} has no value commitment or verification key")]
    MissingEffect(#[error(not(source))] Slot),
    /// Two actions have the same descriptor.
    #[display("{_0} repeats a descriptor")]
    DuplicateDescriptor(#[error(not(source))] Slot),
    /// The value balance leaves its range.
    #[display("value balance out of range")]
    BalanceOverflow,
    /// The value commitments do not balance against the value balance.
    #[display("value commitments do not balance")]
    Unbalanced,
}

/// The randomizers of a bundle's effects, and its bundle commitment.
struct Effects {
    /// Each spend's randomizer, and whether the deriving key owns it.
    spends: Vec<(ActionRandomizer<effect::Spend>, bool)>,
    outputs: Vec<ActionRandomizer<effect::Output>>,
    commitment: [u8; 32],
}

#[expect(clippy::multiple_inherent_impl, reason = "one impl block per role")]
impl Bundle {
    /// Fix the bundle's effects as a planner holding `pak`, and return the
    /// bundle commitment.
    ///
    /// Fills every absent `theta` and `rcv`, and derives each action's `cv`
    /// and `rk` and the max fee note's `cv_feemax`. A spend's `rk` uses its
    /// owner's key. An absent spend owner is filled with `pak`'s validating
    /// key when deriving that spend's effects. An output or max fee note
    /// owned by `pak`'s key takes `pak`'s payment key.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] if a note is incomplete, two actions share a
    /// descriptor, or the value balance leaves its range.
    pub fn finalize_effects<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        pak: &ProofAuthorizingKey,
    ) -> Result<[u8; 32], SignerError> {
        self.derive_effects(rng, &pak.ak, pak.derive_payment_key())
            .map(|effects| effects.commitment)
    }

    /// Authorize the bundle as custody holding `sk`, and return the sighash.
    ///
    /// Custody fixes the effects as [`Self::finalize_effects`] does, under its
    /// own keys. It fills absent fields and never overwrites present ones, and
    /// it computes the bundle commitment and sighash from its own derivation,
    /// not from stored `cv`, `rk` or `cv_feemax`. It signs every unsigned
    /// spend it owns and every unsigned output.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] if a note is incomplete, two actions share a
    /// descriptor, or the value balance leaves its range.
    pub fn authorize<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        sk: &private::SpendingKey,
        compute_sighash: impl FnOnce(&[u8; 32]) -> [u8; 32],
    ) -> Result<[u8; 32], SignerError> {
        let ask = sk.derive_auth_private();
        let effects =
            self.derive_effects(rng, &ask.derive_auth_public(), sk.derive_payment_key())?;
        let sighash = compute_sighash(&effects.commitment);

        for (spend, (alpha, owned)) in self.spends.iter_mut().zip(effects.spends) {
            if owned && spend.sig.is_none() {
                spend.sig = Some(ask.derive_action_private(&alpha).sign(rng, &sighash));
            }
        }
        for (output, alpha) in self.outputs.iter_mut().zip(effects.outputs) {
            if output.sig.is_none() {
                output.sig = Some(private::ActionSigningKey::new(&alpha).sign(rng, &sighash));
            }
        }

        Ok(sighash)
    }

    /// Sign every unsigned output with its randomizer, as a planner holding
    /// each output's `theta`.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] if an unsigned output has an incomplete note or
    /// no `theta`.
    pub fn sign_outputs<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        sighash: &[u8; 32],
    ) -> Result<(), SignerError> {
        for (index, output) in self.outputs.iter_mut().enumerate() {
            if output.sig.is_none() {
                let note = output
                    .note
                    .note()
                    .ok_or(SignerError::MissingNote(Slot::Output(index)))?;
                let theta = output
                    .theta
                    .ok_or(SignerError::MissingEntropy(Slot::Output(index)))?;
                let alpha = theta.randomizer::<effect::Output>(note.commitment());
                output.sig = Some(private::ActionSigningKey::new(&alpha).sign(rng, sighash));
            }
        }
        Ok(())
    }

    /// Sign the binding signature if it is absent.
    ///
    /// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i \boxplus r$, where $r$ is the
    /// max fee note's blind. Before signing, checks that
    /// $[\mathsf{bsk}]\mathcal{R}$ equals the binding verification key of the
    /// stored `cv`, `cv_feemax` and value balance.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] if a trapdoor, the max fee note or a stored
    /// effect is absent, or if the stored effects do not balance.
    pub fn sign_binding<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        sighash: &[u8; 32],
    ) -> Result<(), SignerError> {
        let max_fee_note = self
            .max_fee_note
            .note()
            .ok_or(SignerError::MissingNote(Slot::MaxFee))?;

        let mut trapdoors = Vec::with_capacity(self.spends.len() + self.outputs.len() + 1);
        let mut cvs = Vec::with_capacity(self.spends.len() + self.outputs.len() + 1);
        for (slot, rcv, cv) in self
            .spends
            .iter()
            .enumerate()
            .map(|(index, spend)| (Slot::Spend(index), spend.rcv, spend.cv))
            .chain(
                self.outputs
                    .iter()
                    .enumerate()
                    .map(|(index, output)| (Slot::Output(index), output.rcv, output.cv)),
            )
        {
            trapdoors.push(rcv.ok_or(SignerError::MissingEntropy(slot))?);
            cvs.push(cv.ok_or(SignerError::MissingEffect(slot))?);
        }
        trapdoors.push(max_fee_note.derive_feemax_blind());
        cvs.push(
            self.cv_feemax
                .ok_or(SignerError::MissingEffect(Slot::MaxFee))?,
        );

        let bsk = private::BindingSigningKey::from(trapdoors);
        if bsk.derive_binding_public()
            != public::BindingVerificationKey::derive(cvs, self.value_balance)
        {
            return Err(SignerError::Unbalanced);
        }

        self.binding_sig
            .get_or_insert_with(|| bsk.sign(rng, sighash));
        Ok(())
    }

    /// The bundle commitment of the stored effects, the bundle's
    /// contribution to the transaction sighash.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::MissingEffect`] if an action has no `cv` or `rk`,
    /// or the max fee note no `cv_feemax`.
    pub fn commitment(&self) -> Result<[u8; 32], SignerError> {
        let mut descriptors = Vec::with_capacity(self.spends.len() + self.outputs.len());
        for (slot, cv, rk) in self
            .spends
            .iter()
            .enumerate()
            .map(|(index, spend)| (Slot::Spend(index), spend.cv, spend.rk))
            .chain(
                self.outputs
                    .iter()
                    .enumerate()
                    .map(|(index, output)| (Slot::Output(index), output.cv, output.rk)),
            )
        {
            descriptors.push(action::Descriptor {
                cv: cv.ok_or(SignerError::MissingEffect(slot))?,
                rk: rk.ok_or(SignerError::MissingEffect(slot))?,
            });
        }
        descriptors.sort();

        let cv_feemax = self
            .cv_feemax
            .ok_or(SignerError::MissingEffect(Slot::MaxFee))?;

        Ok(blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&Vec::<[u8; 64]>::from_iter(descriptors)),
            self.value_balance.into(),
            &cv_feemax.into(),
            &blake2b::memo_digest(&self.memo),
        ))
    }

    /// Fix the effects under `ak` and `pk`, filling absent fields, and derive
    /// the bundle commitment from this derivation alone.
    fn derive_effects<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        ak: &SpendValidatingKey,
        pk: PaymentKey,
    ) -> Result<Effects, SignerError> {
        let mut descriptors = BTreeSet::new();
        let mut balance = 0i128;

        let mut spends = Vec::with_capacity(self.spends.len());
        for (index, spend) in self.spends.iter_mut().enumerate() {
            let slot = Slot::Spend(index);
            let note = spend.note.note().ok_or(SignerError::MissingNote(slot))?;
            let theta = *spend
                .theta
                .get_or_insert_with(|| ActionEntropy::random(rng));
            let rcv = *spend
                .rcv
                .get_or_insert_with(|| value::Trapdoor::random(rng));
            let alpha = theta.randomizer::<effect::Spend>(note.commitment());
            let owner = spend.owner.unwrap_or(*ak);
            let descriptor = action::Descriptor {
                cv: effect::Spend::commit_value(rcv, note.value),
                rk: owner.derive_action_public(&alpha),
            };
            if !descriptors.insert(descriptor) {
                return Err(SignerError::DuplicateDescriptor(slot));
            }
            // Record the owner with the derived effects so a later custody
            // does not reinterpret an unspecified owner as its own key.
            spend.owner.get_or_insert(owner);
            spend.cv.get_or_insert(descriptor.cv);
            spend.rk.get_or_insert(descriptor.rk);
            balance += i128::from(note.value);
            spends.push((alpha, owner == *ak));
        }

        let mut outputs = Vec::with_capacity(self.outputs.len());
        for (index, output) in self.outputs.iter_mut().enumerate() {
            let slot = Slot::Output(index);
            let note = owned_note(&mut output.note, output.owner, ak, pk)
                .ok_or(SignerError::MissingNote(slot))?;
            let theta = *output
                .theta
                .get_or_insert_with(|| ActionEntropy::random(rng));
            let rcv = *output
                .rcv
                .get_or_insert_with(|| value::Trapdoor::random(rng));
            let alpha = theta.randomizer::<effect::Output>(note.commitment());
            let descriptor = action::Descriptor {
                cv: effect::Output::commit_value(rcv, note.value),
                rk: private::ActionSigningKey::new(&alpha).derive_action_public(),
            };
            output.cv.get_or_insert(descriptor.cv);
            output.rk.get_or_insert(descriptor.rk);
            if !descriptors.insert(descriptor) {
                return Err(SignerError::DuplicateDescriptor(slot));
            }
            balance -= i128::from(note.value);
            outputs.push(alpha);
        }

        let max_fee_note = owned_note(&mut self.max_fee_note, self.max_fee_owner, ak, pk)
            .ok_or(SignerError::MissingNote(Slot::MaxFee))?;
        let cv_feemax = max_fee_note.cv_feemax();
        self.cv_feemax.get_or_insert(cv_feemax);
        balance -= i128::from(max_fee_note.value);

        let value_balance =
            value::Balance::try_from(balance).map_err(|_err| SignerError::BalanceOverflow)?;

        let commitment = blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&Vec::<[u8; 64]>::from_iter(descriptors)),
            value_balance.into(),
            &cv_feemax.into(),
            &blake2b::memo_digest(&self.memo),
        );

        Ok(Effects {
            spends,
            outputs,
            commitment,
        })
    }
}

/// The note of an output or max fee note under `ak` and `pk`.
///
/// A note owned by `ak` takes `pk`, which fills an absent payment key. Any
/// other note keeps its stored payment key.
fn owned_note(
    opening: &mut NoteOpening,
    owner: Option<SpendValidatingKey>,
    ak: &SpendValidatingKey,
    pk: PaymentKey,
) -> Option<crate::Note> {
    if owner.as_ref() == Some(ak) {
        opening.pk.get_or_insert(pk);
        NoteOpening {
            pk: Some(pk),
            ..*opening
        }
        .note()
    } else {
        opening.note()
    }
}
