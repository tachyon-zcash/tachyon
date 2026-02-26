//! Tachyon Action descriptions.

use core::ops::Neg as _;

use rand::{CryptoRng, RngCore};
use reddsa::orchard::SpendAuth;

use crate::{
    keys::{ProofAuthorizingKey, private, public},
    note::Note,
    value,
    witness::ActionPrivate,
};

/// An unsigned Tachyon action — assembled but not yet authorized.
///
/// Contains the public effecting data `(cv, rk)` for a single action.
/// Produced during the assembly phase of transaction construction.
/// After computing the transaction-wide [`SigHash`](crate::bundle::SigHash),
/// each unsigned action is signed to produce a full [`Action`].
///
/// ## Fields
///
/// - `cv`: Commitment to a net value effect
/// - `rk`: Public key (randomized counterpart to `rsk`)
///
/// ## Note
///
/// The tachygram (nullifier or note commitment) is NOT part of the action.
/// Tachygrams are collected separately in the [`Stamp`](crate::Stamp).
/// However, `rk` is not a direct input to the Ragu proof — each `rk` is
/// cryptographically bound to its corresponding tachygram, which *is* a proof
/// input, so the proof validates `rk` transitively.
///
/// This separation allows the stamp to be stripped during aggregation
/// while the action (with its authorization) remains in the transaction.
#[derive(Clone, Copy, Debug)]
#[expect(
    clippy::module_name_repetitions,
    reason = "UnsignedAction is the natural name for unsigned actions"
)]
pub struct UnsignedAction {
    /// Value commitment $\mathsf{cv} = [v]\,\mathcal{V}
    /// + [\mathsf{rcv}]\,\mathcal{R}$ (EpAffine).
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$ (EpAffine).
    pub rk: public::ActionVerificationKey,
}

impl UnsignedAction {
    /// Assemble an unsigned spend action.
    ///
    /// Computes the value commitment and derives `rk` from the spend
    /// validating key `ak` and the per-action randomizer. No signing
    /// key (`ask`) is needed — `rk` is derived from the public key:
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    ///
    /// The returned [`ActionPrivate`] contains the proof witness
    /// (alpha, note, rcv) needed for stamp construction.
    pub fn spend<R: RngCore + CryptoRng>(
        note: Note,
        theta: &private::ActionEntropy,
        pak: &ProofAuthorizingKey,
        rng: &mut R,
    ) -> (Self, ActionPrivate) {
        // 1. Note commitment
        let cm = note.commitment();

        // 2. Value commitment (signer picks rcv)
        let value: i64 = note.value.into();
        let rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let cv = rcv.commit(value);

        // 3. Alpha derivation + rk computation (from public key ak)
        let alpha = theta.spend_randomizer(&cm);
        let rk = pak.ak().derive_action_public(&alpha);

        (
            Self { cv, rk },
            ActionPrivate {
                alpha: alpha.into(),
                note,
                rcv,
            },
        )
    }

    /// Assemble an unsigned output action.
    ///
    /// Computes the value commitment (negated for outputs) and derives
    /// $\mathsf{rk} = [\alpha]\,\mathcal{G}$ (no spending authority).
    ///
    /// The returned [`ActionPrivate`] contains the proof witness
    /// (alpha, note, rcv) needed for stamp construction.
    pub fn output<R: RngCore + CryptoRng>(
        note: Note,
        theta: &private::ActionEntropy,
        rng: &mut R,
    ) -> (Self, ActionPrivate) {
        // 1. Note commitment
        let cm = note.commitment();

        // 2. Value commitment (signer picks rcv; negative for outputs)
        let value: i64 = note.value.into();
        let rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let cv = rcv.commit(value.neg());

        // 3. Alpha derivation + rk = [alpha]G
        let alpha = theta.output_randomizer(&cm);
        let rk = alpha.derive_rk();

        (
            Self { cv, rk },
            ActionPrivate {
                alpha: alpha.into(),
                note,
                rcv,
            },
        )
    }

    /// Attach a signature to produce a signed [`Action`].
    #[must_use]
    pub const fn sign(self, sig: Signature) -> Action {
        Action {
            cv: self.cv,
            rk: self.rk,
            sig,
        }
    }
}

/// A signed Tachyon Action description.
///
/// ## Fields
///
/// - `cv`: Commitment to a net value effect
/// - `rk`: Public key (randomized counterpart to `rsk`)
/// - `sig`: Signature by private key (single-use `rsk`) over the
///   transaction-wide [`SigHash`](crate::bundle::SigHash)
#[derive(Clone, Copy, Debug)]
pub struct Action {
    /// Value commitment $\mathsf{cv} = [v]\,\mathcal{V}
    /// + [\mathsf{rcv}]\,\mathcal{R}$ (EpAffine).
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$ (EpAffine).
    pub rk: public::ActionVerificationKey,

    /// RedPallas spend auth signature over the transaction-wide
    /// [`SigHash`](crate::bundle::SigHash).
    pub sig: Signature,
}

/// A spend authorization signature (RedPallas over SpendAuth).
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct Signature(pub(crate) reddsa::Signature<SpendAuth>);

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(reddsa::Signature::<SpendAuth>::from(bytes))
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> [u8; 64] {
        <[u8; 64]>::from(sig.0)
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::{Fp, Fq};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        bundle,
        custody::{self, Custody as _, SpendRequest},
        note::{self, CommitmentTrapdoor, NullifierTrapdoor},
    };

    /// A spend action's signature must verify against the transaction-wide
    /// sighash using its own rk.
    #[test]
    fn spend_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let theta = private::ActionEntropy::random(&mut rng);

        // Phase 1: assemble unsigned action
        let (unsigned, _witness) = UnsignedAction::spend(note, &theta, &pak, &mut rng);

        // Phase 2: compute sighash, sign via custody
        let sighash = bundle::sighash(&[unsigned], 1000);
        let local = custody::Local::new(sk.derive_auth_private());
        let cm = note.commitment();
        let sigs = local
            .authorize(
                &[unsigned],
                1000,
                &[SpendRequest {
                    action_index: 0,
                    theta,
                    cm,
                }],
                &mut rng,
            )
            .unwrap();

        unsigned.rk.verify(sighash, &sigs[0]).unwrap();
    }

    /// An output action's signature must verify against the transaction-wide
    /// sighash using its own rk.
    #[test]
    fn output_sig_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let theta = private::ActionEntropy::random(&mut rng);

        // Phase 1: assemble unsigned action
        let (unsigned, _witness) = UnsignedAction::output(note, &theta, &mut rng);

        // Phase 2: compute sighash, sign with output randomizer
        let sighash = bundle::sighash(&[unsigned], -1000);
        let cm = note.commitment();
        let alpha = theta.output_randomizer(&cm);
        let sig = alpha.sign(sighash, &mut rng);

        unsigned.rk.verify(sighash, &sig).unwrap();
    }
}
