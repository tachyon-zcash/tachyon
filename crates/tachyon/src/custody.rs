//! Authorization of a bundle by the custody device.
//!
//! The planner selects each action's note, `theta` and `rcv`, and sends
//! them as a [`Request`]. Every signed value is derived from the request.
//! Nothing supplied is checked.
//!
//! - [`Request::plan`] derives each action's descriptor under `ak`.
//! - [`Request::authorize`] derives the same descriptors under `ask` and signs
//!   every action.
//! - [`Planned::apply_signatures`] attaches action signatures made elsewhere.
//! - [`Request::sign_binding`] signs the binding signature. Custody or the
//!   planner may call it.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::ops::Neg as _;

use derive_more::{Debug, Display, Eq as TotalEq, Error, PartialEq};
use rand_core::CryptoRng;

use crate::{
    action::{self, Action},
    bundle::{self, Bundle},
    digest::blake2b,
    entropy::ActionEntropy,
    keys::{SpendValidatingKey, private},
    note::Note,
    primitives::{Anchor, Effect as _, effect},
    stamp::{self, Unproven},
    value,
};

/// Errors that can occur while planning or authorizing a request.
#[derive(Clone, Copy, Debug, Display, Error, PartialEq, TotalEq)]
#[non_exhaustive]
pub enum RequestError {
    /// The value balance overflows the representable range.
    #[display("value balance overflow")]
    BalanceOverflow,
    /// The signatures do not match the planned actions.
    #[display("planned actions do not match signed actions")]
    ActionSigMismatch,
}

/// One action of a [`Request`], chosen by the planner.
#[derive(Clone, Copy, Debug)]
pub struct RequestAction {
    /// The note being spent or created.
    pub note: Note,
    /// Per-action entropy for alpha derivation.
    pub theta: ActionEntropy,
    /// Value commitment trapdoor.
    pub rcv: value::Trapdoor,
}

/// Everything custody needs to authorize a bundle.
#[derive(Clone, Debug)]
pub struct Request {
    /// Spend actions.
    pub spends: Vec<RequestAction>,
    /// Output actions.
    pub outputs: Vec<RequestAction>,
    /// Opaque recipient-directed payload, empty when absent.
    pub memo: Vec<u8>,
}

/// Every action's descriptor and the bundle's effecting data, in request
/// order on each side.
#[derive(Clone, Debug)]
pub struct Planned {
    spends: Vec<action::Descriptor>,
    outputs: Vec<action::Descriptor>,
    value_balance: value::Balance,
    memo: Vec<u8>,
}

/// A [`Planned`] bundle with a signature on every action.
#[derive(Clone, Debug)]
pub struct Authorized {
    planned: Planned,
    signatures: BTreeMap<action::Descriptor, action::Signature>,
    sighash: [u8; 32],
}

impl Request {
    /// Derive every action's descriptor under `ak`, and the value balance.
    ///
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\mathcal{G}$ for a spend and
    /// $\mathsf{rk} = [\alpha]\mathcal{G}$ for an output.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::BalanceOverflow`] if the value balance falls
    /// outside `-MAX_MONEY..=MAX_MONEY`.
    pub fn plan(&self, ak: &SpendValidatingKey) -> Result<Planned, RequestError> {
        let spends = self
            .spends
            .iter()
            .map(|act| action::Descriptor {
                cv: effect::Spend::commit_value(act.rcv, act.note.value),
                rk: ak.derive_action_public(&act.theta.randomizer(act.note.commitment())),
            })
            .collect();

        let outputs = self
            .outputs
            .iter()
            .map(|act| action::Descriptor {
                cv: effect::Output::commit_value(act.rcv, act.note.value),
                rk: private::ActionSigningKey::new(&act.theta.randomizer(act.note.commitment()))
                    .derive_action_public(),
            })
            .collect();

        let value_balance = value::Balance::try_from(
            self.spends
                .iter()
                .map(|act| i128::from(act.note.value))
                .chain(
                    self.outputs
                        .iter()
                        .map(|act| i128::from(act.note.value).neg()),
                )
                .sum::<i128>(),
        )
        .map_err(|_err| RequestError::BalanceOverflow)?;

        Ok(Planned {
            spends,
            outputs,
            value_balance,
            memo: self.memo.clone(),
        })
    }

    /// Derive every action under `ask`, compute the transaction sighash from
    /// the bundle commitment with `compute_sighash`, and sign every action.
    ///
    /// A spend signs with $\mathsf{ask} + \alpha$ and an output with
    /// $\alpha$.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::BalanceOverflow`] as [`Self::plan`] does.
    pub fn authorize<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        ask: &private::SpendAuthorizingKey,
        compute_sighash: impl FnOnce(&[u8; 32]) -> [u8; 32],
    ) -> Result<Authorized, RequestError> {
        let planned = self.plan(&ask.derive_auth_public())?;
        let sighash = compute_sighash(&planned.commitment());

        let mut signatures = BTreeMap::new();
        for (act, desc) in self.spends.iter().zip(&planned.spends) {
            let alpha = act.theta.randomizer(act.note.commitment());
            let rsk = ask.derive_action_private(&alpha);
            signatures.insert(*desc, rsk.sign(rng, &sighash));
        }
        for (act, desc) in self.outputs.iter().zip(&planned.outputs) {
            let alpha = act.theta.randomizer(act.note.commitment());
            let rsk = private::ActionSigningKey::new(&alpha);
            signatures.insert(*desc, rsk.sign(rng, &sighash));
        }

        Ok(Authorized {
            planned,
            signatures,
            sighash,
        })
    }

    /// Sign `sighash` with the binding signing key.
    ///
    /// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$.
    pub fn sign_binding<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        sighash: &[u8; 32],
    ) -> bundle::Signature {
        private::BindingSigningKey::from(self.spends.iter().chain(&self.outputs).map(|act| act.rcv))
            .sign(rng, sighash)
    }
}

impl Planned {
    /// The spend descriptors, in request order.
    #[must_use]
    pub fn spends(&self) -> &[action::Descriptor] {
        &self.spends
    }

    /// The output descriptors, in request order.
    #[must_use]
    pub fn outputs(&self) -> &[action::Descriptor] {
        &self.outputs
    }

    /// The value balance, spends minus outputs.
    #[must_use]
    pub const fn value_balance(&self) -> value::Balance {
        self.value_balance
    }

    /// The bundle commitment, over the descriptors in sorted order.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let descriptors: Vec<[u8; 64]> = self
            .spends
            .iter()
            .chain(&self.outputs)
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&descriptors),
            self.value_balance.into(),
            &blake2b::memo_digest(&self.memo),
        )
    }

    /// Attach action signatures made outside custody over `sighash`.
    ///
    /// To confirm the signatures, call [`Bundle::verify_signatures`] on the
    /// bundle.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::ActionSigMismatch`] if the signed descriptors
    /// differ from the planned ones.
    pub fn apply_signatures(
        self,
        sighash: [u8; 32],
        signatures: BTreeMap<action::Descriptor, action::Signature>,
    ) -> Result<Authorized, RequestError> {
        let planned: BTreeSet<action::Descriptor> =
            self.spends.iter().chain(&self.outputs).copied().collect();
        if !planned.iter().eq(signatures.keys()) {
            return Err(RequestError::ActionSigMismatch);
        }

        Ok(Authorized {
            planned: self,
            signatures,
            sighash,
        })
    }
}

impl Authorized {
    /// The transaction sighash every action signed.
    #[must_use]
    pub const fn sighash(&self) -> &[u8; 32] {
        &self.sighash
    }

    /// Assemble the unproven bundle, with actions in descriptor order.
    #[must_use]
    pub fn bundle(&self, binding_sig: bundle::Signature) -> Bundle<Unproven> {
        Bundle {
            actions: self
                .signatures
                .iter()
                .map(|(desc, sig)| Action::from((*desc, *sig)))
                .collect(),
            value_balance: self.planned.value_balance,
            binding_sig,
            memo: self.planned.memo.clone(),
            stamp: Unproven,
        }
    }

    /// Build the [`stamp::Plan`] for `request`, the request these
    /// signatures authorize.
    #[must_use]
    pub fn stamp_plan(&self, request: &Request, anchor: Anchor) -> stamp::Plan {
        let spends = request
            .spends
            .iter()
            .zip(&self.planned.spends)
            .map(|(act, desc)| (*desc, act.theta, act.rcv))
            .collect();

        let outputs = request
            .outputs
            .iter()
            .zip(&self.planned.outputs)
            .map(|(act, desc)| (*desc, act.theta, act.note, act.rcv))
            .collect();

        stamp::Plan::new(spends, outputs, anchor)
    }
}
