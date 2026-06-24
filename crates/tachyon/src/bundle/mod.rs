//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by stamp state `S: StampState`.
//! Actions are constant through state transitions; only the stamp changes.
//!
//! - `Bundle<Stamp>` — self-contained bundle with a stamp
//! - `Bundle<AggregateId>` — stamp removed, references the covering aggregate
//! - [`TachyonBundle`] — enum of stamped-or-stripped for mixed contexts
//!
//! # Consensus wire format
//!
//! The first byte `tachyonBundleState` selects one of three bundle states:
//!
//! | value         | state       | bundle contents                       |
//! | ------------- | ----------- | ------------------------------------- |
//! | `0b0000_0000` | non-tachyon | no bundle                             |
//! | `0b0000_0001` | stamped     | bundle with anchor, tachygrams, proof |
//! | `0b0000_0010` | stripped    | bundle with aggregate's wtxid         |
//! | `...`         | *reserved*  | *n/a*                                 |
//!
//! Any other byte is invalid. Stripped innocents and stripped adjuncts share
//! the same wire layout (both write `0x02` + body + a nonzero 64-byte `wtxid`
//! naming the covering aggregate).
//!
//! ## No Bundle
//!
//! When `tachyonBundleState` is 0x00, there is no bundle.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `tachyonBundleState`  | u8                   | `0x00`                                   |
//!
//! ## Tachyon Bundle
//!
//! When `tachyonBundleState` is not 0x00, there is a tachyon bundle.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `tachyonBundleState`  | u8                   | `0x01` or `0x02`                         |
//! | `valueBalanceTachyon` | i64                  | net value of tachyon actions             |
//! | `nActionsTachyon`     | compactsize          | number of tachyon actions                |
//! | `vActionsTachyon`     | 64 * nActionsTachyon | (cv: 32 bytes, rk: 32 bytes)             |
//! | `vActionSigsTachyon`  | 64 * nActionsTachyon | authorization per action over tx sighash |
//! | `bindingSigTachyon`   | 64 bytes             | binding over tx sighash                  |
//!
//! ### Stamp trailer
//!
//! When `tachyonBundleState == 1`, there is a stamp trailer.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `cActionsTachyon`     | 32 bytes             | action set for this proof                |
//! | `anchorTachyon`       | 32 bytes             | pool state reference                     |
//! | `nTachygrams`         | compactsize          | number of tachygrams                     |
//! | `vTachygrams`         | 32 * nTachygrams     | tachygrams for this proof                |
//! | `proofTachyon`        | PROOF_SIZE blob      | serialized proof of fixed size           |
//!
//! ## Stripped trailer
//!
//! When `tachyonBundleState == 2`, there is a stripped trailer.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `tachyonAggregateId`  | 64 bytes             | wtxid of the relevant aggregate          |

use alloc::vec::Vec;
use core::ops;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, From, PartialEq};
use ff::PrimeField as _;
use group::GroupEncoding as _;
use pasta_curves::{Eq, Fp};
use rand_core::{CryptoRng, RngCore};

pub use crate::digest::blake2b::{AUTH_DIGEST_NO_BUNDLE, COMMIT_NO_BUNDLE};
use crate::{
    ActionSetPoly,
    action::{self, Action},
    digest::blake2b,
    keys::{private, public},
    note,
    primitives::{ActionDigest, ActionDigestError, Anchor, effect},
    reddsa, serialization,
    stamp::{self, AggregateId, Stamp, Stripped, Unproven},
    value,
};

/// The `tachyonBundleState` wire byte. See the module-level wire format
/// documentation for its role.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
#[repr(u8)]
enum BundleState {
    NoBundle = 0b0000_0000u8,
    Stamped = 0b0000_0001u8,
    Stripped = 0b0000_0010u8,
}

impl BundleState {
    pub(super) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        match u8::from_le_bytes(byte) {
            0b0000_0000u8 => Ok(Self::NoBundle),
            0b0000_0001u8 => Ok(Self::Stamped),
            0b0000_0010u8 => Ok(Self::Stripped),
            _other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid bundle state",
            )),
        }
    }

    pub(super) fn write<W: Write>(self, mut writer: W) -> io::Result<()> {
        let byte = u8::to_le_bytes(match self {
            Self::NoBundle => 0b0000_0000u8,
            Self::Stamped => 0b0000_0001u8,
            Self::Stripped => 0b0000_0010u8,
        });
        writer.write_all(&byte)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Unproven {}
    impl Sealed for super::Stamp {}
    impl Sealed for super::AggregateId {}
    impl Sealed for super::Stripped {}
}

/// Sealed trait constraining stamp state types.
pub trait StampState: sealed::Sealed {}
impl<T: sealed::Sealed> StampState for T {}

/// A Tachyon transaction bundle parameterized by stamp state `S`.
#[derive(Clone, Debug, PartialEq, TotalEq)]
pub struct Bundle<S: StampState> {
    /// Actions (cv, rk, sig).
    pub actions: Vec<Action>,

    /// Net value of spends minus outputs (plaintext integer).
    pub value_balance: i64,

    /// Binding signature over the transaction sighash.
    pub binding_sig: Signature,

    /// Stamp state: `Unproven`, `Stamp`, `Stripped`, or `AggregateId`.
    pub stamp: S,
}

/// A Tachyon bundle in one of its two on-wire states: stamped or stripped.
///
/// Used where code accepts either form — reading from the wire, dispatching
/// `auth_digest`, etc. The `Unproven` and `Stripped` intermediate states are
/// outside this enum because they have no wire representation.
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
#[derive(Clone, Debug, From)]
pub enum TachyonBundle {
    /// A bundle with its own stamp (autonome or aggregate).
    Stamped(Bundle<Stamp>),
    /// A bundle whose stamp has been stripped; carries a reference to the
    /// covering aggregate via its [`AggregateId`].
    Adjunct(Bundle<AggregateId>),
}

impl TryFrom<TachyonBundle> for Bundle<Stamp> {
    type Error = Bundle<AggregateId>;

    fn try_from(bundle: TachyonBundle) -> Result<Self, Self::Error> {
        match bundle {
            TachyonBundle::Adjunct(stripped) => Err(stripped),
            TachyonBundle::Stamped(stamped) => Ok(stamped),
        }
    }
}

impl TryFrom<TachyonBundle> for Bundle<AggregateId> {
    type Error = Bundle<Stamp>;

    fn try_from(bundle: TachyonBundle) -> Result<Self, Self::Error> {
        match bundle {
            TachyonBundle::Adjunct(stripped) => Ok(stripped),
            TachyonBundle::Stamped(stamped) => Err(stamped),
        }
    }
}

/// Errors during bundle construction.
#[derive(Clone, Copy, Debug, Display, Error)]
pub enum BuildError {
    /// Ragu proof verification failed.
    #[display("proof verification failed")]
    ProofInvalid,

    /// BSK/BVK mismatch (see Protocol §4.14).
    #[display("binding signing key does not match verification key")]
    BalanceKeyMismatch,
}

/// Errors that can occur when computing a bundle plan commitment.
#[derive(Debug, Display, Error, From)]
#[non_exhaustive]
pub enum CommitError {
    /// An action digest could not be constructed.
    #[display("action digest: {_0}")]
    ActionDigest(#[error(not(source))] ActionDigestError),
    /// The value balance overflows the representable range.
    #[display("value balance overflow")]
    BalanceOverflow(#[error(not(source))] BalanceError),
}

/// Errors from bundle signature verification.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// The binding signature is invalid.
    #[display("invalid binding signature {_0:?}")]
    Binding(#[error(not(source))] Signature),
    /// An action signature is invalid.
    #[display("invalid action signature {_0:?}")]
    Action(#[error(not(source))] action::Signature),
}

/// Errors that can occur while signing a bundle plan.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum SignError {
    /// The derived rk does not match the stored rk.
    #[display("plan rk {rk:?} does not match at action {index}")]
    RkMismatch {
        /// Index of the offending action in the bundle (spends first, then
        /// outputs).
        #[error(not(source))]
        index: usize,
        /// The stored rk that did not match the derived one.
        #[error(not(source))]
        rk: reddsa::VerificationKeyBytes<reddsa::ActionAuth>,
    },
    /// The number of signatures does not match the number of actions.
    #[display("expected {_0} signatures")]
    SigCountMismatch(#[error(not(source))] usize),
    /// An externally-provided signature is invalid.
    #[display("signature {:?} does not verify", _0)]
    InvalidActionSignature(#[error(not(source))] action::Signature),
    /// The value balance overflows the representable range.
    #[display("value balance overflow")]
    BalanceOverflow,
}

/// A complete bundle plan, awaiting authorization.
#[derive(Clone, Debug)]
pub struct Plan {
    /// Spend action plans.
    pub spends: Vec<action::Plan<effect::Spend>>,

    /// Output action plans.
    pub outputs: Vec<action::Plan<effect::Output>>,
}

impl Plan {
    /// Create a new bundle plan from assembled action plans.
    #[must_use]
    pub const fn new(
        spends: Vec<action::Plan<effect::Spend>>,
        outputs: Vec<action::Plan<effect::Output>>,
    ) -> Self {
        Self { spends, outputs }
    }

    /// Iterate over all actions in the plan, mapping with the provided
    /// functions. It is equivalent to calling `transform_spend` for each spend
    /// and `transform_output` for each output.
    pub fn iter_actions<T>(
        &self,
        transform_spend: impl Fn(&action::Plan<effect::Spend>) -> T,
        transform_output: impl Fn(&action::Plan<effect::Output>) -> T,
    ) -> impl Iterator<Item = T> {
        let spend_transform = self.spends.iter().map(transform_spend);
        let output_transform = self.outputs.iter().map(transform_output);
        spend_transform.chain(output_transform)
    }

    /// Derive value_balance from note values.
    ///
    /// $\mathsf{v\_balance} = \sum_i v_{\text{spend},i} - \sum_j
    /// v_{\text{output},j}$
    ///
    /// Returns `Err` if the intermediate sum overflows or the result
    /// does not fit in `i64`.
    pub fn value_balance(&self) -> Result<i64, BalanceError> {
        let mut sum = ValueBalance::ZERO;
        for plan in &self.spends {
            sum = (sum + plan.note.value)?;
        }
        for plan in &self.outputs {
            sum = (sum - plan.note.value)?;
        }
        i64::try_from(sum)
    }

    /// Compute a digest of all the bundle's effecting data.
    ///
    /// This contributes to the transaction sighash.
    ///
    /// $$ \mathsf{bundle\_commitment} = \text{BLAKE2b-256}(
    /// \text{"ZTxIdTachyonHash"},\;
    /// \mathsf{encoding}(\mathsf{action\_acc}) \|
    /// \mathsf{value\_balance}) $$
    ///
    /// where $\mathsf{action\_acc}$ is the polynomial commitment to the
    /// action digest multiset `∏(X - action_digest_i)` — order-independent
    /// by construction since the polynomial is invariant under root
    /// permutation — digested as its 32-byte point encoding.
    ///
    /// The stamp is excluded because it is stripped during aggregation.
    pub fn commitment(&self) -> Result<[u8; 32], CommitError> {
        let digests: Vec<ActionDigest> = self
            .iter_actions(action::Plan::digest, action::Plan::digest)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()?;

        let action_commit = ActionSetPoly::from_iter(digests).commit();

        Ok(blake2b::bundle_commitment(
            &Eq::from(action_commit).to_bytes(),
            self.value_balance()?,
        ))
    }

    /// Build a [`stamp::Plan`] from this bundle plan.
    ///
    /// Derives alpha from theta for each action and collects the proof
    /// witnesses. The returned plan is ready to prove with
    /// [`stamp::Plan::prove`].
    #[must_use]
    pub fn stamp_plan(&self, anchor: Anchor) -> stamp::Plan {
        let spends = self
            .spends
            .iter()
            .map(|plan| {
                let alpha = plan.theta.randomizer(plan.note.commitment());
                ((plan.cv(), plan.rk), (alpha, plan.note, plan.rcv))
            })
            .collect();

        let outputs = self
            .outputs
            .iter()
            .map(|plan| {
                let alpha = plan.theta.randomizer(plan.note.commitment());
                ((plan.cv(), plan.rk), (alpha, plan.note, plan.rcv))
            })
            .collect();

        stamp::Plan::new(spends, outputs, anchor)
    }

    /// Derive the binding signing key, which is the scalar sum of value
    /// commitment trapdoors.
    ///
    /// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$.
    #[must_use]
    pub fn derive_bsk_private(&self) -> private::BindingSigningKey {
        let trapdoors: Vec<_> = self
            .iter_actions(|plan| plan.rcv, |plan| plan.rcv)
            .collect();
        private::BindingSigningKey::from(trapdoors.as_slice())
    }

    /// Sign all actions with a spend authorizing key.
    ///
    /// For each action, independently derives alpha from theta + note
    /// commitment, verifies the derived rk matches, and signs. Also
    /// derives the binding signing key from rcvs and signs the binding
    /// signature.
    ///
    /// The result is a `Bundle<Unproven>` — combine with a [`Stamp`] via
    /// [`Bundle::stamp`] to produce a `Bundle<Stamp>`.
    pub fn sign<RNG: RngCore + CryptoRng>(
        &self,
        sighash: &[u8; 32],
        ask: &private::SpendAuthorizingKey,
        rng: &mut RNG,
    ) -> Result<Bundle<Unproven>, SignError> {
        let n_actions = self.spends.len() + self.outputs.len();
        let mut authorized = Vec::with_capacity(n_actions);

        for (index, plan) in self.spends.iter().enumerate() {
            let cm = plan.note.commitment();
            let alpha = plan.theta.randomizer::<effect::Spend>(cm);
            let rsk = ask.derive_action_private(&alpha);
            if rsk.derive_action_public() != plan.rk {
                return Err(SignError::RkMismatch {
                    index,
                    rk: plan.rk.0.into(),
                });
            }
            authorized.push(Action {
                cv: plan.cv(),
                rk: plan.rk,
                sig: rsk.sign(rng, sighash),
            });
        }

        for (idx, plan) in self.outputs.iter().enumerate() {
            let cm = plan.note.commitment();
            let alpha = plan.theta.randomizer::<effect::Output>(cm);
            let rsk = private::ActionSigningKey::new(&alpha);
            if rsk.derive_action_public() != plan.rk {
                return Err(SignError::RkMismatch {
                    index: self.spends.len() + idx,
                    rk: plan.rk.0.into(),
                });
            }
            authorized.push(Action {
                cv: plan.cv(),
                rk: plan.rk,
                sig: rsk.sign(rng, sighash),
            });
        }

        let bsk = self.derive_bsk_private();
        let binding_sig = bsk.sign(rng, sighash);

        Ok(Bundle {
            actions: authorized,
            value_balance: self
                .value_balance()
                .map_err(|_err| SignError::BalanceOverflow)?,
            binding_sig,
            stamp: Unproven,
        })
    }

    /// Apply externally-produced signatures (e.g. from FROST).
    ///
    /// Validates each signature against the action's rk and the sighash.
    /// Derives cv from each plan and produces the binding signature.
    pub fn apply_signatures<RNG: RngCore + CryptoRng>(
        &self,
        sighash: &[u8; 32],
        sigs: Vec<action::Signature>,
        rng: &mut RNG,
    ) -> Result<Bundle<Unproven>, SignError> {
        let n_actions = self.spends.len() + self.outputs.len();
        if sigs.len() != n_actions {
            return Err(SignError::SigCountMismatch(n_actions));
        }

        let mut authorized = Vec::with_capacity(n_actions);

        let all_descriptors = self
            .iter_actions(|plan| (plan.cv(), plan.rk), |plan| (plan.cv(), plan.rk))
            .zip(sigs);

        for ((cv, rk), sig) in all_descriptors {
            if rk.verify(sighash, &sig).is_err() {
                return Err(SignError::InvalidActionSignature(sig));
            }
            authorized.push(Action { cv, rk, sig });
        }

        let bsk = self.derive_bsk_private();
        let binding_sig = bsk.sign(rng, sighash);

        Ok(Bundle {
            actions: authorized,
            value_balance: self
                .value_balance()
                .map_err(|_err| SignError::BalanceOverflow)?,
            binding_sig,
            stamp: Unproven,
        })
    }
}

impl Bundle<Unproven> {
    /// Attach a stamp, producing a `Bundle<Stamp>`.
    #[must_use]
    pub fn stamp(self, stamp: Stamp) -> Bundle<Stamp> {
        Bundle {
            actions: self.actions,
            value_balance: self.value_balance,
            binding_sig: self.binding_sig,
            stamp,
        }
    }
}

impl Bundle<Stripped> {
    /// Assign the covering aggregate's `wtxid`, producing a serializable
    /// `Bundle<AggregateId>`.
    ///
    /// This is the only path from [`strip()`](Bundle::strip) to a wire-ready
    /// stripped bundle — `Bundle<Stripped>` has no `write()` method. The
    /// `wtxid` is an already-validated nonzero [`AggregateId`], so every
    /// stripped bundle (innocent or adjunct) names a covering aggregate.
    #[must_use]
    pub fn assign_wtxid(self, wtxid: AggregateId) -> Bundle<AggregateId> {
        Bundle {
            actions: self.actions,
            value_balance: self.value_balance,
            binding_sig: self.binding_sig,
            stamp: wtxid,
        }
    }
}

impl Bundle<Stamp> {
    /// Strips the stamp, producing an unassigned bundle and the extracted
    /// stamp.
    ///
    /// The returned `Bundle<Stripped>` must be assigned a covering
    /// aggregate's `wtxid` via [`assign_wtxid`](Bundle::assign_wtxid)
    /// before it can be serialized. The stamp should be merged into an
    /// aggregate.
    #[must_use]
    pub fn strip(self) -> (Bundle<Stripped>, Stamp) {
        (
            Bundle {
                actions: self.actions,
                value_balance: self.value_balance,
                binding_sig: self.binding_sig,
                stamp: Stripped,
            },
            self.stamp,
        )
    }

    /// Confirm published coverage without verifying the proof: reconstruct the
    /// action-set commitment from this bundle's actions plus every adjunct's
    /// and check it against the carried `cActionsTachyon`. Assistive, not
    /// soundness.
    pub fn covers<T: StampState>(
        &self,
        associates: &[Bundle<T>],
    ) -> Result<bool, ActionDigestError> {
        let associate_actions = associates.iter().flat_map(|adjunct| adjunct.actions.iter());

        let cover_actions = self.actions.iter().chain(associate_actions);

        let cover_digests = cover_actions
            .map(Action::digest)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()?;

        let cover_set = cover_digests.into_iter().collect::<ActionSetPoly>();

        Ok(cover_set.commit() == self.stamp.action_set)
    }

    /// Read a stamped bundle from the consensus wire format.
    ///
    /// Expects `tachyonBundleState == 0x01`. See the module-level wire format
    /// documentation.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let head = BundleState::read(&mut reader)?;

        if head != BundleState::Stamped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stamped bundle requires tachyonBundleState 0x01",
            ));
        }

        let (actions, value_balance, binding_sig): (Vec<Action>, i64, Signature) =
            read_bundle_body(&mut reader)?;

        let stamp = Stamp::read(&mut reader)?;

        Ok(Self {
            actions,
            value_balance,
            binding_sig,
            stamp,
        })
    }

    /// Write a stamped bundle in the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        BundleState::Stamped.write(&mut writer)?;

        write_bundle_body(
            &mut writer,
            &self.actions,
            self.value_balance,
            &self.binding_sig,
        )?;

        self.stamp.write(&mut writer)?;

        Ok(())
    }

    /// Tachyon's contribution to the transaction `auth_digest`.
    ///
    /// Hashes action signatures, the binding signature, and the stamp
    /// trailer's field encodings.
    #[must_use]
    pub fn auth_digest(&self) -> [u8; 32] {
        let action_sigs: Vec<[u8; 64]> = self.actions.iter().map(|act| act.sig.into()).collect();
        let binding_sig: [u8; 64] = self.binding_sig.into();

        let trailer = {
            let action_set: [u8; 32] = Eq::from(self.stamp.action_set).to_bytes();
            let anchor: [u8; 32] = self.stamp.anchor.0.into();
            let tachygrams: Vec<[u8; 32]> = self
                .stamp
                .tachygrams
                .iter()
                .map(|&tg| Fp::from(tg).to_repr())
                .collect();
            let proof = self.stamp.proof.serialize();
            (action_set, anchor, tachygrams, proof)
        };

        blake2b::stamped_auth_digest(
            &action_sigs,
            &binding_sig,
            &trailer.0,
            &trailer.1,
            &trailer.2,
            trailer.3.as_ref(),
        )
    }
}

impl Bundle<AggregateId> {
    /// Read a stripped bundle from the consensus wire format.
    ///
    /// Expects `tachyonBundleState` 0x02. Always reads a nonzero 64-byte
    /// `stampWtxid` trailer; [`AggregateId::read`] rejects the all-zero
    /// encoding. See the module-level wire format documentation.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let head = BundleState::read(&mut reader)?;

        if head != BundleState::Stripped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stripped bundle requires tachyonBundleState 0x02",
            ));
        }

        let (actions, value_balance, binding_sig) = read_bundle_body(&mut reader)?;

        let stamp = AggregateId::read(&mut reader)?;

        Ok(Self {
            actions,
            value_balance,
            binding_sig,
            stamp,
        })
    }

    /// Write a stripped bundle in the consensus wire format.
    ///
    /// Always writes flag `0x02` and a nonzero 64-byte `stampWtxid` trailer.
    /// The trailer names the covering aggregate for every stripped bundle,
    /// innocent or adjunct; [`AggregateId`] cannot hold the all-zero value.
    ///
    /// Miners assign the covering aggregate's wtxid during block assembly,
    /// locating it via tachygram matching against the original autonome
    /// broadcast.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        BundleState::Stripped.write(&mut writer)?;

        write_bundle_body(
            &mut writer,
            &self.actions,
            self.value_balance,
            &self.binding_sig,
        )?;

        self.stamp.write(&mut writer)
    }

    /// Tachyon's contribution to the transaction `auth_digest`.
    ///
    /// Hashes action signatures, the binding signature, and the stripped
    /// trailer: the 64-byte `wtxid` of the covering aggregate.
    #[must_use]
    pub fn auth_digest(&self) -> [u8; 32] {
        let action_sigs: Vec<[u8; 64]> = self.actions.iter().map(|act| act.sig.into()).collect();
        let binding_sig: [u8; 64] = self.binding_sig.into();
        blake2b::stripped_auth_digest(&action_sigs, &binding_sig, &self.stamp.into())
    }
}

impl TachyonBundle {
    /// Read any Tachyon bundle from the consensus wire format, dispatching
    /// on the `tachyonBundleState` byte.
    ///
    /// Expects a stamped (`0x01`) or stripped (`0x02`) bundle; rejects
    /// `0x00` (non-tachyon — the caller should decide absence at its own
    /// layer) and any other byte.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Option<Self>> {
        // TODO: just peek at state, then delegate to the appropriate read method
        let state = BundleState::read(&mut reader)?;

        Ok(match state {
            BundleState::NoBundle => None,
            BundleState::Stamped => {
                let (actions, value_balance, binding_sig) = read_bundle_body(&mut reader)?;
                Some(Self::Stamped(Bundle {
                    actions,
                    value_balance,
                    binding_sig,
                    stamp: Stamp::read(&mut reader)?,
                }))
            },
            BundleState::Stripped => {
                let (actions, value_balance, binding_sig) = read_bundle_body(&mut reader)?;
                let stamp = AggregateId::read(&mut reader)?;

                Some(Self::Adjunct(Bundle {
                    actions,
                    value_balance,
                    binding_sig,
                    stamp,
                }))
            },
        })
    }

    /// Write any Tachyon bundle in the consensus wire format, dispatching on
    /// the variant.
    #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        match *self {
            Self::Stamped(ref stamped) => stamped.write(writer),
            Self::Adjunct(ref stripped) => stripped.write(writer),
        }
    }

    /// Tachyon's contribution to the transaction `auth_digest`, dispatching
    /// on the variant. See the `auth_digest` methods on `Bundle<Stamp>` and
    /// `Bundle<AggregateId>`.
    #[must_use]
    #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
    pub fn auth_digest(&self) -> [u8; 32] {
        match *self {
            Self::Stamped(ref stamped) => stamped.auth_digest(),
            Self::Adjunct(ref stripped) => stripped.auth_digest(),
        }
    }
}

impl<S: StampState> Bundle<S> {
    /// See [`Plan::commitment`].
    pub fn commitment(&self) -> Result<[u8; 32], ActionDigestError> {
        let action_digests = self
            .actions
            .iter()
            .map(Action::digest)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()?;
        let action_acc = ActionSetPoly::from_iter(action_digests).commit();
        Ok(blake2b::bundle_commitment(
            &Eq::from(action_acc).to_bytes(),
            self.value_balance,
        ))
    }

    /// Verify the bundle's binding signature and all action signatures.
    pub fn verify_signatures(&self, sighash: &[u8; 32]) -> Result<(), SignatureError> {
        // 1. Derive bvk from public data (validator-side, §4.14)
        let bvk = public::BindingVerificationKey::derive(&self.actions, self.value_balance);

        // 2. Verify binding signature
        bvk.verify(sighash, &self.binding_sig)
            .map_err(|_err| SignatureError::Binding(self.binding_sig))?;

        // 3. Verify each action signature against the SAME sighash
        for action in &self.actions {
            action
                .rk
                .verify(sighash, &action.sig)
                .map_err(|_err| SignatureError::Action(action.sig))?;
        }

        Ok(())
    }
}

/// Signed sum of note values across actions.
///
/// Spends contribute positive values, outputs contribute negative.
/// Uses `i128` internally to provide additional headroom while accumulating
/// values. Checked arithmetic still reports overflow, and conversion to the
/// wire-format `i64` fails if the final balance is out of range.
///
/// Use `i64::try_from(sum)` to narrow to the wire-format `i64`.
#[derive(Clone, Copy, Debug, Default, PartialEq, TotalEq)]
pub struct ValueBalance(i128);

/// Error returned when a [`ValueBalance`] operation overflows the
/// representable range.
#[derive(Clone, Copy, Debug, Display, Error)]
#[display("value balance overflow")]
pub struct BalanceError;

impl ValueBalance {
    /// The zero sum (identity for addition).
    pub const ZERO: Self = Self(0);
}

impl TryFrom<ValueBalance> for i64 {
    type Error = BalanceError;

    // This doesn't need to check against NOTE_VALUE_MAX
    fn try_from(sum: ValueBalance) -> Result<Self, Self::Error> {
        Self::try_from(sum.0).map_err(|_err| BalanceError)
    }
}

impl ops::Add<note::Value> for ValueBalance {
    type Output = Result<Self, BalanceError>;

    fn add(self, rhs: note::Value) -> Self::Output {
        self.0
            .checked_add(u64::from(rhs).into())
            .map(Self)
            .ok_or(BalanceError)
    }
}

impl ops::Sub<note::Value> for ValueBalance {
    type Output = Result<Self, BalanceError>;

    fn sub(self, rhs: note::Value) -> Self::Output {
        self.0
            .checked_sub(u64::from(rhs).into())
            .map(Self)
            .ok_or(BalanceError)
    }
}

/// A binding signature (RedPallas over the Binding group).
///
/// Proves the signer knew the opening $\mathsf{bsk}$ of the Pedersen
/// commitment $\mathsf{bvk}$ to value 0. By the **binding property**
/// of the commitment scheme, it is infeasible to find
/// $(v^*, \mathsf{bsk}')$ such that
/// $\mathsf{bvk} = \text{ValueCommit}_{\mathsf{bsk}'}(v^*)$ for
/// $v^* \neq 0$ — so value balance is enforced.
///
/// The signed message is the transaction sighash — a transaction-wide
/// digest computed at the transaction layer. The validator checks:
/// $\text{BindingSig.Validate}_{\mathsf{bvk}}(\mathsf{sighash},
///   \text{bindingSig}) = 1$
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct Signature(pub(crate) reddsa::Signature<reddsa::BindingAuth>);

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes.into())
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> Self {
        sig.0.into()
    }
}

/// Read bundle fields: value balance, action descriptors, action sigs,
/// and binding sig.
fn read_bundle_body<R: Read>(mut reader: R) -> io::Result<(Vec<Action>, i64, Signature)> {
    let mut vb_bytes = [0u8; 8];
    reader.read_exact(&mut vb_bytes)?;
    let value_balance = i64::from_le_bytes(vb_bytes);

    let n_actions =
        usize::try_from(serialization::read_compactsize(&mut reader)?).map_err(|_err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "actions vector length exceeds usize",
            )
        })?;

    let mut descriptors = Vec::with_capacity(n_actions);
    for _ in 0..n_actions {
        let cv = value::Commitment(serialization::read_ep_affine(&mut reader)?);
        let rk = public::ActionVerificationKey(serialization::read_action_vk(&mut reader)?);
        descriptors.push((cv, rk));
    }

    let mut signatures = Vec::with_capacity(n_actions);
    for _ in 0..n_actions {
        let sig = action::Signature(serialization::read_action_sig(&mut reader)?);
        signatures.push(sig);
    }

    let actions = descriptors
        .iter()
        .zip(signatures.iter())
        .map(|(&(cv, rk), &sig)| Action { cv, rk, sig })
        .collect();

    let binding_sig = Signature(serialization::read_binding_sig(&mut reader)?);

    Ok((actions, value_balance, binding_sig))
}

/// Write bundle fields: value balance, action descriptors, action sigs,
/// and binding sig.
fn write_bundle_body<W: Write>(
    mut writer: W,
    actions: &[Action],
    value_balance: i64,
    binding_sig: &Signature,
) -> io::Result<()> {
    writer.write_all(&value_balance.to_le_bytes())?;

    serialization::write_compactsize(
        &mut writer,
        u64::try_from(actions.len()).map_err(|_err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "actions vector length exceeds u64",
            )
        })?,
    )?;
    for action in actions {
        serialization::write_ep_affine(&mut writer, &action.cv.0)?;
        serialization::write_action_vk(&mut writer, &action.rk.0)?;
    }
    for action in actions {
        serialization::write_action_sig(&mut writer, &action.sig.0)?;
    }

    serialization::write_binding_sig(&mut writer, &binding_sig.0)?;

    Ok(())
}

#[cfg(test)]
mod tests;
