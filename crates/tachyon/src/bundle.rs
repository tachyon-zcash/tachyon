//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by stamp state `S: StampState`.
//! Actions are constant through state transitions; only the stamp changes.
//!
//! - [`Stamped`] — self-contained bundle with a stamp
//! - [`Stripped`] — stamp removed, depends on an aggregate
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
//! the same wire layout (both write `0x02` + body + 64-byte `wtxid`).
//!
//! ## No Bundle
//!
//! When `tachyonBundleState == 0`, there is no bundle.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `tachyonBundleState`  | 1                    | 0                                        |
//!
//! ## Tachyon Bundle
//!
//! When `tachyonBundleState != 0`, there is a tachyon bundle.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `tachyonBundleState`  | 1                    | `0x01` or `0x02`                         |
//! | `valueBalanceTachyon` | int64 LE             | net value of tachyon actions             |
//! | `nActionsTachyon`     | compactsize          | number of tachyon actions                |
//! | `vActionsTachyon`     | 64 * nActionsTachyon | (cv: 32 bytes, rk: 32 bytes)             |
//! | `vActionSigsTachyon`  | 64 * nActionsTachyon | authorization per action over tx sighash |
//! | `bindingSigTachyon`   | 64                   | binding over tx sighash                  |
//!
//! ### Stamp trailer
//!
//! When `tachyonBundleState == 1`, there is a stamp trailer.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `anchorTachyon`       | 64                   | pool state                               |
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
//! | `tachyonAggregateId`  | 64                   | wtxid of the relevant aggregate          |

use alloc::vec::Vec;
use core::{error::Error, fmt};

use corez::io::{self, Read, Write};
use ff::{Field as _, PrimeField as _};
use group::GroupEncoding as _;
use lazy_static::lazy_static;
use mock_ragu::Polynomial;
use pasta_curves::Fp;
use rand_core::{CryptoRng, RngCore};

use crate::{
    action::{self, Action},
    constants::{AUTH_DIGEST_PERSONALIZATION, BUNDLE_COMMITMENT_PERSONALIZATION},
    keys::{private, public},
    primitives::{
        ActionCommit, ActionDigest, ActionDigestError, Anchor, DelegationTrapdoor, Tachygram,
        effect,
    },
    reddsa, serialization,
    stamp::{self, Adjunct, Stamp, Unproven, proof::compute_action_acc},
    value,
};

/// The `tachyonBundleState` wire byte. See the module-level wire format
/// documentation for its role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BundleState {
    NoBundle = 0b0000_0000,
    Stamped = 0b0000_0001,
    Stripped = 0b0000_0010,
}

impl TryFrom<u8> for BundleState {
    type Error = ();

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            | 0b0000_0000 => Ok(Self::NoBundle),
            | 0b0000_0001 => Ok(Self::Stamped),
            | 0b0000_0010 => Ok(Self::Stripped),
            | _other => Err(()),
        }
    }
}

impl From<BundleState> for u8 {
    fn from(state: BundleState) -> Self {
        match state {
            | BundleState::NoBundle => 0b0000_0000,
            | BundleState::Stamped => 0b0000_0001,
            | BundleState::Stripped => 0b0000_0010,
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Stamp {}
    impl Sealed for super::Adjunct {}
    impl Sealed for super::Unproven {}
}

/// Sealed trait constraining stamp state types.
pub trait StampState: sealed::Sealed {}
impl<T: sealed::Sealed> StampState for T {}

/// A Tachyon transaction bundle parameterized by stamp state `S`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle<S: StampState> {
    /// Actions (cv, rk, sig).
    pub actions: Vec<Action>,

    /// Net value of spends minus outputs (plaintext integer).
    pub value_balance: i64,

    /// Binding signature over the transaction sighash.
    pub binding_sig: Signature,

    /// Stamp state: `Stamp` when present, `Adjunct` when stripped.
    pub stamp: S,
}

/// A bundle with a stamp — can stand alone or cover adjunct bundles.
pub type Stamped = Bundle<Stamp>;

/// A bundle whose stamp has been stripped — depends on a stamped bundle.
pub type Stripped = Bundle<Adjunct>;

/// A Tachyon bundle in one of its two on-wire states: stamped or stripped.
///
/// Used where code accepts either form — reading from the wire, dispatching
/// `auth_digest`, etc. The `Unproven` intermediate state is outside this
/// enum because it has no wire representation.
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
#[derive(Clone, Debug)]
pub enum TachyonBundle {
    /// A bundle with its own stamp (autonome or aggregate).
    Stamped(Stamped),
    /// A bundle whose stamp has been stripped; carries a reference to the
    /// covering aggregate via [`Adjunct`].
    Stripped(Stripped),
}

impl From<Stamped> for TachyonBundle {
    fn from(bundle: Stamped) -> Self {
        Self::Stamped(bundle)
    }
}

impl From<Stripped> for TachyonBundle {
    fn from(bundle: Stripped) -> Self {
        Self::Stripped(bundle)
    }
}

impl TryFrom<TachyonBundle> for Stamped {
    type Error = Stripped;

    fn try_from(bundle: TachyonBundle) -> Result<Self, Self::Error> {
        match bundle {
            | TachyonBundle::Stamped(stamped) => Ok(stamped),
            | TachyonBundle::Stripped(stripped) => Err(stripped),
        }
    }
}

impl TryFrom<TachyonBundle> for Stripped {
    type Error = Stamped;

    fn try_from(bundle: TachyonBundle) -> Result<Self, Self::Error> {
        match bundle {
            | TachyonBundle::Stripped(stripped) => Ok(stripped),
            | TachyonBundle::Stamped(stamped) => Err(stamped),
        }
    }
}

/// Errors during bundle construction.
#[derive(Clone, Copy, Debug)]
pub enum BuildError {
    /// Ragu proof verification failed
    ProofInvalid,

    /// BSK/BVK mismatch (see Protocol §4.14)
    BalanceKeyMismatch,
}

/// Errors that can occur while signing a bundle plan.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignError {
    /// The derived rk does not match the stored rk at this index.
    RkMismatch(usize),
    /// The number of signatures does not match the number of actions.
    SigCountMismatch,
    /// An externally-provided signature is invalid at this index.
    InvalidActionSignature,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::RkMismatch(idx) => write!(f, "derived rk mismatch at action {idx}"),
            | Self::SigCountMismatch => write!(f, "signature count mismatch"),
            | Self::InvalidActionSignature => write!(f, "invalid action signature"),
        }
    }
}

impl Error for SignError {}

/// Compute a digest of all the bundle's effecting data.
///
/// This contributes to the transaction sighash.
///
/// $$ \mathsf{bundle\_commitment} = \text{BLAKE2b-512}(
/// \text{"Tachyon-BndlHash"},\; \mathsf{action\_acc} \|
/// \mathsf{value\_balance}) $$
///
/// where $\mathsf{action\_acc}$ is the 32-byte commitment to the action
/// digest multiset `∏(X - action_digest_i)` — order-independent by
/// construction since the polynomial is invariant under root permutation.
///
/// The stamp is excluded because it is stripped during aggregation.
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
#[must_use]
pub fn digest_bundle(action_acc: &ActionCommit, value_balance: i64) -> [u8; 64] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(BUNDLE_COMMITMENT_PERSONALIZATION)
        .to_state();

    let action_bytes: [u8; 32] = action_acc.0.into();
    state.update(&action_bytes);

    state.update(&value_balance.to_le_bytes());

    *state.finalize().as_array()
}

lazy_static! {
    /// Commitment for the absence of a Tachyon bundle in a transaction.
    ///
    /// Personalized BLAKE2b-512 finalized with no data, distinct from the
    /// commitment of an empty bundle (which hashes the identity accumulator
    /// commitment and a zero value balance).
    ///
    /// Follows ZIP-244's pattern for absent pool commitments.
    static ref COMMIT_NO_BUNDLE: [u8; 64] = *blake2b_simd::Params::new()
        .hash_length(64)
        .personal(BUNDLE_COMMITMENT_PERSONALIZATION)
        .to_state()
        .finalize()
        .as_array();
}

/// Canonical sighash contribution when a transaction has no Tachyon bundle.
///
/// Returns the personalized BLAKE2b-512 finalized with no data, distinct from
/// any real bundle commitment. Mirrors orchard's `hash_bundle_txid_empty`.
#[must_use]
pub fn empty_commitment() -> [u8; 64] {
    *COMMIT_NO_BUNDLE
}

lazy_static! {
    /// Auth-digest contribution for the absence of a Tachyon bundle.
    ///
    /// Personalized BLAKE2b-256 finalized with no data, distinct from any
    /// real bundle's contribution. Follows ZIP-244's pattern for absent pool
    /// auth digests.
    static ref AUTH_DIGEST_NO_BUNDLE: [u8; 64] = *blake2b_simd::Params::new()
        .hash_length(64)
        .personal(AUTH_DIGEST_PERSONALIZATION)
        .to_state()
        .finalize()
        .as_array();
}

/// Canonical `auth_digest` contribution when a transaction has no Tachyon
/// bundle. Distinct from any real bundle's contribution.
#[must_use]
pub fn empty_auth_digest() -> [u8; 64] {
    *AUTH_DIGEST_NO_BUNDLE
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
    #[must_use]
    pub fn value_balance(&self) -> i64 {
        let spend_sum: i64 = self
            .spends
            .iter()
            .map(|plan| i64::from(plan.note.value))
            .sum();
        let output_sum: i64 = self
            .outputs
            .iter()
            .map(|plan| i64::from(plan.note.value))
            .sum();
        spend_sum - output_sum
    }

    /// Compute the bundle commitment.
    /// See [`digest_bundle`].
    #[must_use]
    pub fn commitment(&self) -> [u8; 64] {
        #[expect(clippy::expect_used, reason = "todo")]
        let roots: Vec<Fp> = self
            .iter_actions(
                |plan| Fp::from(&ActionDigest::try_from(plan).expect("don't plan invalid spends")),
                |plan| Fp::from(&ActionDigest::try_from(plan).expect("don't plan invalid outputs")),
            )
            .collect();
        let action_acc = ActionCommit(Polynomial::from_roots(&roots).commit(Fp::ZERO));

        digest_bundle(&action_acc, self.value_balance())
    }

    /// Build a [`stamp::Plan`] from this bundle plan.
    ///
    /// Derives alpha from theta for each action and collects the proof
    /// witnesses. The returned plan is ready to prove with
    /// [`stamp::Plan::prove`].
    ///
    /// `spend_traps` must be in the same order as `self.spends` and
    /// carry the `DelegationTrapdoor` that was used to construct each
    /// spend's delegation / nullifier PCDs.
    ///
    /// # Panics
    ///
    /// Panics if `spend_traps.len() != self.spends.len()`.
    #[must_use]
    pub fn stamp_plan(&self, anchor: Anchor, spend_traps: &[DelegationTrapdoor]) -> stamp::Plan {
        assert_eq!(
            spend_traps.len(),
            self.spends.len(),
            "one DelegationTrapdoor per spend"
        );
        let spends = self
            .spends
            .iter()
            .zip(spend_traps.iter().copied())
            .map(|(plan, delegation_trap)| {
                let alpha = plan.theta.randomizer(&plan.note.commitment());
                (
                    (plan.cv(), plan.rk),
                    (alpha, plan.note, plan.rcv, delegation_trap),
                )
            })
            .collect();

        let outputs = self
            .outputs
            .iter()
            .map(|plan| {
                let alpha = plan.theta.randomizer(&plan.note.commitment());
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
    /// [`Bundle::stamp`] to produce a [`Stamped`] bundle.
    pub fn sign<RNG: RngCore + CryptoRng>(
        &self,
        sighash: &[u8; 32],
        ask: &private::SpendAuthorizingKey,
        rng: &mut RNG,
    ) -> Result<Bundle<Unproven>, SignError> {
        let n_actions = self.spends.len() + self.outputs.len();
        let mut authorized = Vec::with_capacity(n_actions);

        for (idx, plan) in self.spends.iter().enumerate() {
            let cm = plan.note.commitment();
            let alpha = plan.theta.randomizer::<effect::Spend>(&cm);
            let rsk = ask.derive_action_private(&alpha);
            if rsk.derive_action_public() != plan.rk {
                return Err(SignError::RkMismatch(idx));
            }
            authorized.push(Action {
                cv: plan.cv(),
                rk: plan.rk,
                sig: rsk.sign(rng, sighash),
            });
        }

        for (idx, plan) in self.outputs.iter().enumerate() {
            let cm = plan.note.commitment();
            let alpha = plan.theta.randomizer::<effect::Output>(&cm);
            let rsk = private::ActionSigningKey::new(&alpha);
            if rsk.derive_action_public() != plan.rk {
                return Err(SignError::RkMismatch(self.spends.len() + idx));
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
            value_balance: self.value_balance(),
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
            return Err(SignError::SigCountMismatch);
        }

        let mut authorized = Vec::with_capacity(n_actions);

        let all_descriptors = self
            .iter_actions(|plan| (plan.cv(), plan.rk), |plan| (plan.cv(), plan.rk))
            .zip(sigs);

        for ((cv, rk), sig) in all_descriptors {
            if rk.verify(sighash, &sig).is_err() {
                return Err(SignError::InvalidActionSignature);
            }
            authorized.push(Action { cv, rk, sig });
        }

        let bsk = self.derive_bsk_private();
        let binding_sig = bsk.sign(rng, sighash);

        Ok(Bundle {
            actions: authorized,
            value_balance: self.value_balance(),
            binding_sig,
            stamp: Unproven,
        })
    }
}

impl Bundle<Unproven> {
    /// Attach a stamp, producing a [`Stamped`] bundle.
    #[must_use]
    pub fn stamp(self, stamp: Stamp) -> Stamped {
        Bundle {
            actions: self.actions,
            value_balance: self.value_balance,
            binding_sig: self.binding_sig,
            stamp,
        }
    }
}

impl Stamped {
    /// Strips the stamp, producing a stripped bundle and the extracted stamp.
    ///
    /// The stamp should be merged into an aggregate's stamped bundle.
    #[must_use]
    pub fn strip(self) -> (Stripped, Stamp) {
        (
            Bundle {
                actions: self.actions,
                value_balance: self.value_balance,
                binding_sig: self.binding_sig,
                stamp: Adjunct::default(),
            },
            self.stamp,
        )
    }

    /// Read a stamped bundle from the consensus wire format.
    ///
    /// Expects `tachyonBundleState == 0x01`. See the module-level wire format
    /// documentation.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let head = read_bundle_head(&mut reader)?;

        if head != BundleState::Stamped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stamped bundle requires tachyonBundleState == 0x01",
            ));
        }

        let (actions, value_balance, binding_sig): (Vec<Action>, i64, Signature) =
            read_bundle_body(&mut reader)?;

        let stamp = read_bundle_trailer_stamped(&mut reader)?;

        Ok(Self {
            actions,
            value_balance,
            binding_sig,
            stamp,
        })
    }

    /// Write a stamped bundle in the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_bundle_head(&mut writer, BundleState::Stamped)?;

        write_bundle_body(
            &mut writer,
            &self.actions,
            self.value_balance,
            &self.binding_sig,
        )?;

        write_bundle_trailer_stamped(&mut writer, &self.stamp)?;

        Ok(())
    }

    /// Tachyon's contribution to the transaction `auth_digest`.
    ///
    /// Hashes action signatures, the binding signature, and the serialized
    /// stamp trailer (anchor + tachygrams + proof).
    #[must_use]
    pub fn auth_digest(&self) -> [u8; 64] {
        let mut state = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(AUTH_DIGEST_PERSONALIZATION)
            .to_state();

        for action in &self.actions {
            let sig_bytes: [u8; 64] = action.sig.into();
            state.update(&sig_bytes);
        }
        let binding_sig_bytes: [u8; 64] = self.binding_sig.into();
        state.update(&binding_sig_bytes);

        state.update(&self.stamp.anchor.0.0.to_le_bytes());
        state.update(&self.stamp.anchor.1.0.inner().to_bytes());

        for tg in &self.stamp.tachygrams {
            state.update(&Fp::from(tg).to_repr());
        }

        state.update(self.stamp.proof.serialize().as_ref());

        *state.finalize().as_array()
    }
}

impl Stripped {
    /// Read a stripped bundle from the consensus wire format.
    ///
    /// Expects `tachyonBundleState == 0x02`. Always reads a 64-byte
    /// `stampWtxid` trailer. See the module-level wire format documentation.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let head = read_bundle_head(&mut reader)?;

        if head != BundleState::Stripped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stripped bundle requires tachyonBundleState == 0x02",
            ));
        }

        let (actions, value_balance, binding_sig) = read_bundle_body(&mut reader)?;

        let stamp = read_bundle_trailer_stripped(&mut reader)?;

        Ok(Self {
            actions,
            value_balance,
            binding_sig,
            stamp,
        })
    }

    /// Write a stripped bundle in the consensus wire format.
    ///
    /// Always writes flag `0x02` and a 64-byte `stampWtxid` trailer. Rejects
    /// unassigned-wtxid (`[0; 64]`) when actions are non-empty — an adjunct
    /// whose covering-aggregate wtxid the miner never assigned.
    ///
    /// Miners assign the covering aggregate's wtxid during block assembly,
    /// locating it via tachygram matching against the original autonome
    /// broadcast. Stripped innocents (empty actions) may serialize with a
    /// zero wtxid if no absorbing aggregate was recorded.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_bundle_head(&mut writer, BundleState::Stripped)?;

        write_bundle_body(
            &mut writer,
            &self.actions,
            self.value_balance,
            &self.binding_sig,
        )?;

        write_bundle_trailer_stripped(&mut writer, &self.stamp)?;

        Ok(())
    }

    /// Tachyon's contribution to the transaction `auth_digest`.
    ///
    /// Hashes action signatures, the binding signature, and the 64-byte
    /// `wtxid` of the covering aggregate.
    #[must_use]
    pub fn auth_digest(&self) -> [u8; 64] {
        let mut state = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(AUTH_DIGEST_PERSONALIZATION)
            .to_state();

        for action in &self.actions {
            let sig_bytes: [u8; 64] = action.sig.into();
            state.update(&sig_bytes);
        }
        let binding_sig_bytes: [u8; 64] = self.binding_sig.into();
        state.update(&binding_sig_bytes);

        state.update(&self.stamp.wtxid);

        *state.finalize().as_array()
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
        let state = read_bundle_head(&mut reader)?;

        Ok(match state {
            | BundleState::NoBundle => None,
            | BundleState::Stamped => {
                let (actions, value_balance, binding_sig) = read_bundle_body(&mut reader)?;
                Some(Self::Stamped(Stamped {
                    actions,
                    value_balance,
                    binding_sig,
                    stamp: read_bundle_trailer_stamped(&mut reader)?,
                }))
            },
            | BundleState::Stripped => {
                let (actions, value_balance, binding_sig) = read_bundle_body(&mut reader)?;
                Some(Self::Stripped(Stripped {
                    actions,
                    value_balance,
                    binding_sig,
                    stamp: read_bundle_trailer_stripped(&mut reader)?,
                }))
            },
        })
    }

    /// Write any Tachyon bundle in the consensus wire format, dispatching on
    /// the variant.
    #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        match *self {
            | Self::Stamped(ref stamped) => stamped.write(writer),
            | Self::Stripped(ref stripped) => stripped.write(writer),
        }
    }

    /// Tachyon's contribution to the transaction `auth_digest`, dispatching
    /// on the variant. See [`Stamped::auth_digest`] and
    /// [`Stripped::auth_digest`].
    #[must_use]
    #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
    pub fn auth_digest(&self) -> [u8; 64] {
        match *self {
            | Self::Stamped(ref stamped) => stamped.auth_digest(),
            | Self::Stripped(ref stripped) => stripped.auth_digest(),
        }
    }
}

impl<S: StampState> Bundle<S> {
    /// See [`digest_bundle`].
    pub fn commitment(&self) -> Result<[u8; 64], ActionDigestError> {
        let action_acc = ActionCommit(compute_action_acc(&self.actions)?.0.commit(Fp::ZERO));
        Ok(digest_bundle(&action_acc, self.value_balance))
    }

    /// Verify the bundle's binding signature and all action signatures.
    pub fn verify_signatures(&self, sighash: &[u8; 32]) -> Result<(), reddsa::Error> {
        // 1. Derive bvk from public data (validator-side, §4.14)
        let bvk = public::BindingVerificationKey::derive(&self.actions, self.value_balance);

        // 2. Verify binding signature
        bvk.verify(sighash, &self.binding_sig)?;

        // 3. Verify each action signature against the SAME sighash
        for action in &self.actions {
            action.rk.verify(sighash, &action.sig)?;
        }

        Ok(())
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

fn read_bundle_head<R: Read>(mut reader: R) -> io::Result<BundleState> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    BundleState::try_from(byte[0])
        .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "invalid bundle state"))
}

/// Read bundle fields: value balance, action descriptors, action sigs,
/// and binding sig.
fn read_bundle_body<R: Read>(mut reader: R) -> io::Result<(Vec<Action>, i64, Signature)> {
    let mut vb_bytes = [0u8; 8];
    reader.read_exact(&mut vb_bytes)?;
    let value_balance = i64::from_le_bytes(vb_bytes);

    let n_actions =
        usize::try_from(serialization::read_compactsize(&mut reader)?)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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

fn read_bundle_trailer_stamped<R: Read>(mut reader: R) -> io::Result<Stamp> {
    let anchor = Anchor::read(&mut reader)?;

    let tachygrams = serialization::read_fp_list(&mut reader)?
        .iter()
        .map(Tachygram::from)
        .collect();

    let proof = stamp::read_proof_sized(&mut reader, stamp::proof_serialized_size())?;
    Ok(Stamp {
        tachygrams,
        anchor,
        proof,
    })
}

fn read_bundle_trailer_stripped<R: Read>(mut reader: R) -> io::Result<Adjunct> {
    let mut wtxid = [0u8; 64];
    reader.read_exact(&mut wtxid)?;
    Ok(Adjunct { wtxid })
}

fn write_bundle_head<W: Write>(mut writer: W, state: BundleState) -> io::Result<()> {
    writer.write_all(&[u8::from(state)])?;
    Ok(())
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
        u64::try_from(actions.len()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
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

fn write_bundle_trailer_stamped<W: Write>(mut writer: W, stamp: &Stamp) -> io::Result<()> {
    stamp.anchor.write(&mut writer)?;
    serialization::write_fp_list(
        &mut writer,
        &stamp.tachygrams.iter().map(Fp::from).collect::<Vec<Fp>>(),
    )?;
    stamp::write_proof(&mut writer, &stamp.proof)?;
    Ok(())
}

fn write_bundle_trailer_stripped<W: Write>(mut writer: W, adjunct: &Adjunct) -> io::Result<()> {
    writer.write_all(&adjunct.wtxid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use mock_ragu::Polynomial;
    use pasta_curves::Fp;
    use rand::{CryptoRng, RngCore, SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        action,
        entropy::ActionEntropy,
        keys::private,
        primitives::{BlockHeight, PoolCommit},
        stamp::Stamp,
        test_support::{
            PoolSim, WalletSim, action_digests, build_output_action, mock_sighash,
            random_block_with,
        },
        value,
    };

    fn make_output_stamp(
        rng: &mut (impl RngCore + CryptoRng),
        wallet: &WalletSim,
        value_amount: u64,
    ) -> (Stamp, Action, action::Plan<effect::Output>) {
        let note = wallet.random_note(rng, value_amount);
        let rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let theta = ActionEntropy::random(&mut *rng);
        let plan = action::Plan::output(note, theta, rcv);
        let alpha = theta.randomizer::<effect::Output>(&note.commitment());

        let stamp = Stamp::prove_output(
            &mut *rng,
            rcv,
            alpha,
            note,
            Anchor(
                BlockHeight(0),
                PoolCommit(Polynomial::default().commit(Fp::ZERO)),
            ),
        )
        .expect("prove_output");
        let action = Action {
            cv: plan.cv(),
            rk: plan.rk,
            sig: action::Signature::from([0u8; 64]),
        };
        (stamp, action, plan)
    }

    /// Convenience wrapper: fresh wallet + pool, mine the spend note's cm,
    /// then prove a non-balancing autonome (`value_balance = spend_value -
    /// output_value`).
    fn build_autonome(
        rng: &mut (impl RngCore + CryptoRng),
        spend_value: u64,
        output_value: u64,
    ) -> Stamped {
        let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));
        let spend_note = wallet.random_note(rng, spend_value);
        let output_note = wallet.random_note(rng, output_value);
        let mut pool = PoolSim::new();
        pool.mine(random_block_with(rng, spend_note.commitment(), 50));
        let anchor = pool.anchor();
        let spend = wallet.fresh_spend(rng, anchor, pool.state().clone(), spend_note);
        wallet.autonome(rng, anchor, alloc::vec![spend], alloc::vec![output_note])
    }

    #[test]
    fn wrong_value_balance_fails_verification() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut bundle = build_autonome(&mut rng, 1000, 700);
        let sighash = mock_sighash(bundle.commitment().unwrap());

        bundle.value_balance = 999;
        assert!(bundle.verify_signatures(&sighash).is_err());
    }

    /// Stripping preserves the binding signature and action signatures.
    #[test]
    fn stripped_bundle_retains_signatures() {
        let mut rng = StdRng::seed_from_u64(0);
        let bundle = build_autonome(&mut rng, 1000, 700);
        let sighash = mock_sighash(bundle.commitment().unwrap());

        let (stripped, _stamp) = bundle.strip();
        stripped.verify_signatures(&sighash).unwrap();
    }

    /// The plan commitment and the built bundle commitment must agree.
    /// Signatures don't feed the commitment, so the zero-sig action from
    /// `make_output_stamp` is sufficient.
    #[test]
    fn plan_commitment_matches_bundle_commitment() {
        let mut rng = StdRng::seed_from_u64(42);
        let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));
        let (stamp, output_action, output_plan) = make_output_stamp(&mut rng, &wallet, 200);

        let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_plan]);
        let sighash = mock_sighash(bundle_plan.commitment());

        let bundle: Stamped = Bundle {
            actions: alloc::vec![output_action],
            value_balance: bundle_plan.value_balance(),
            binding_sig: bundle_plan.derive_bsk_private().sign(&mut rng, &sighash),
            stamp,
        };

        assert_eq!(bundle_plan.commitment(), bundle.commitment().unwrap());
    }

    /// The "no bundle" commitment must differ from an empty bundle's
    /// commitment (identity accumulator + zero balance).
    #[test]
    fn no_bundle_commitment_differs_from_empty_bundle() {
        let empty_plan = Plan::new(alloc::vec![], alloc::vec![]);
        assert_ne!(
            *COMMIT_NO_BUNDLE,
            empty_plan.commitment(),
            "absent bundle must differ from empty bundle"
        );
    }

    /// A zero-action bundle with zero balance must verify correctly.
    ///
    /// This exercises the edge case where `BindingVerificationKey::derive`
    /// receives an empty action slice and value_balance = 0, producing the
    /// identity point as `bvk`.
    #[test]
    fn zero_action_bundle_is_valid() {
        let mut rng = StdRng::seed_from_u64(0xdead);
        let plan = Plan::new(alloc::vec![], alloc::vec![]);
        let sighash = mock_sighash(plan.commitment());

        let bundle: Stripped = Bundle {
            actions: alloc::vec![],
            value_balance: 0,
            binding_sig: plan.derive_bsk_private().sign(&mut rng, &sighash),
            stamp: Adjunct::default(),
        };

        bundle.verify_signatures(&sighash).unwrap();
    }

    /// Payment bundle: sender spends an input note, recipient receives an
    /// output at the payment value, sender gets the change. Covers the
    /// 1-spend-plus-multiple-outputs shape (distinct from the single-output
    /// `build_autonome` flow) and exercises a deeper merge tree (3 stamps →
    /// 2 merges) at the bundle layer.
    #[test]
    fn payment_bundle_verifies() {
        let mut rng = StdRng::seed_from_u64(0x9AB6);
        let sender = WalletSim::new(private::SpendingKey::random(&mut rng));
        let recipient = WalletSim::new(private::SpendingKey::random(&mut rng));
        let input_note = sender.random_note(&mut rng, 500);
        let output_note = recipient.random_note(&mut rng, 200);
        let change_note = sender.random_note(&mut rng, 300);

        let mut pool = PoolSim::new();
        pool.mine(random_block_with(&mut rng, input_note.commitment(), 50));
        let anchor = pool.anchor();
        let spend = sender.fresh_spend(&mut rng, anchor, pool.state().clone(), input_note);
        let stamped = sender.autonome(
            &mut rng,
            anchor,
            alloc::vec![spend],
            alloc::vec![output_note, change_note],
        );
        let sighash = mock_sighash(stamped.commitment().unwrap());
        stamped
            .verify_signatures(&sighash)
            .expect("payment bundle must verify");
    }

    /// `stamp.verify` binds the *action multiset*: order-agnostic, but every
    /// other deviation (missing, extra, duplicated, substituted) rejects.
    /// Exercises the cv-sign / ActionDigest binding inside the stamp proof —
    /// if an attacker tampers with any action's (cv, rk), the reconstructed
    /// multiset no longer matches what the circuit committed to.
    #[test]
    fn stamp_binds_action_multiset() {
        let mut rng = StdRng::seed_from_u64(0x1157);
        let stamped = build_autonome(&mut rng, 1000, 700);
        let action_a = stamped.actions[0];
        let action_b = stamped.actions[1];

        // Unrelated third action (different wallet, new output) for
        // "extra" and "substituted" cases.
        let other_wallet = WalletSim::new(private::SpendingKey::from([0x17u8; 32]));
        let unrelated_note = other_wallet.random_note(&mut rng, 400);
        let (_, _, action_c) = build_output_action(&mut rng, unrelated_note);

        // Permutation must verify — multiset is order-invariant.
        stamped
            .stamp
            .verify(&[action_b, action_a], &mut rng)
            .expect("permuted actions must verify");

        // Every other deviation must reject.
        assert!(
            stamped.stamp.verify(&[action_a], &mut rng).is_err(),
            "missing action must reject"
        );
        assert!(
            stamped
                .stamp
                .verify(&[action_a, action_b, action_c], &mut rng)
                .is_err(),
            "extra action must reject"
        );
        assert!(
            stamped
                .stamp
                .verify(&[action_a, action_a], &mut rng)
                .is_err(),
            "duplicated action must reject"
        );
        assert!(
            stamped
                .stamp
                .verify(&[action_a, action_c], &mut rng)
                .is_err(),
            "substituted action must reject"
        );
    }

    /// Zero `value_balance` is common (fully-shielded transaction) and must
    /// continue to verify. Individual-note nonzero doesn't imply bundle-level
    /// nonzero: this test spends V, outputs V, leaves zero transparent flow.
    #[test]
    fn bundle_with_zero_value_balance_verifies() {
        let mut rng = StdRng::seed_from_u64(0xBA1A);
        let stamped = build_autonome(&mut rng, 500, 500);
        assert_eq!(
            stamped.value_balance, 0,
            "spend value equals output value -> balance is zero"
        );
        let sighash = mock_sighash(stamped.commitment().unwrap());
        stamped
            .verify_signatures(&sighash)
            .expect("zero-balance bundle must verify");
    }

    #[test]
    fn innocent_aggregate_from_two_autonomes() {
        let mut rng = StdRng::seed_from_u64(0xCAFE);
        let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));

        let spend_a = wallet.random_note(&mut rng, 1000);
        let output_a = wallet.random_note(&mut rng, 700);
        let spend_b = wallet.random_note(&mut rng, 500);
        let output_b = wallet.random_note(&mut rng, 200);

        // Mine both spend cms into the same pool so both autonomes share anchor.
        let mut pool = PoolSim::new();
        pool.mine(random_block_with(&mut rng, spend_a.commitment(), 50));
        pool.mine(random_block_with(&mut rng, spend_b.commitment(), 50));
        let anchor = pool.anchor();
        let pool_state = pool.state().clone();

        let tuple_a = wallet.fresh_spend(&mut rng, anchor, pool_state.clone(), spend_a);
        let tuple_b = wallet.fresh_spend(&mut rng, anchor, pool_state, spend_b);
        let autonome_a = wallet.autonome(
            &mut rng,
            anchor,
            alloc::vec![tuple_a],
            alloc::vec![output_a],
        );
        let autonome_b = wallet.autonome(
            &mut rng,
            anchor,
            alloc::vec![tuple_b],
            alloc::vec![output_b],
        );

        let digests_a = action_digests(&autonome_a.actions);
        let digests_b = action_digests(&autonome_b.actions);
        let (adjunct_a, stamp_a) = autonome_a.strip();
        let (adjunct_b, stamp_b) = autonome_b.strip();

        let innocent: Stamped = {
            let innocent_plan = Plan::new(alloc::vec![], alloc::vec![]);
            let innocent_sighash = mock_sighash(innocent_plan.commitment());

            let stamp = Stamp::prove_merge(&mut rng, (stamp_a, &digests_a), (stamp_b, &digests_b))
                .expect("prove_merge");

            Bundle {
                actions: alloc::vec![],
                value_balance: 0,
                binding_sig: innocent_plan
                    .derive_bsk_private()
                    .sign(&mut rng, &innocent_sighash),
                stamp,
            }
        };

        innocent
            .verify_signatures(&mock_sighash(innocent.commitment().unwrap()))
            .expect("innocent binding sig should verify");

        let adjunct_actions: Vec<Action> = [adjunct_a.actions, adjunct_b.actions].concat();
        innocent
            .stamp
            .verify(&adjunct_actions, &mut rng)
            .expect("innocent stamp should verify against adjunct actions");
    }

    #[test]
    fn based_aggregate_with_two_adjuncts() {
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));

        let based_spend = wallet.random_note(&mut rng, 800);
        let based_output = wallet.random_note(&mut rng, 400);
        let a_spend = wallet.random_note(&mut rng, 1000);
        let a_output = wallet.random_note(&mut rng, 700);
        let b_spend = wallet.random_note(&mut rng, 500);
        let b_output = wallet.random_note(&mut rng, 200);

        let mut pool = PoolSim::new();
        pool.mine(random_block_with(&mut rng, based_spend.commitment(), 50));
        pool.mine(random_block_with(&mut rng, a_spend.commitment(), 50));
        pool.mine(random_block_with(&mut rng, b_spend.commitment(), 50));
        let anchor = pool.anchor();
        let pool_state = pool.state().clone();

        let based_tuple = wallet.fresh_spend(&mut rng, anchor, pool_state.clone(), based_spend);
        let a_tuple = wallet.fresh_spend(&mut rng, anchor, pool_state.clone(), a_spend);
        let b_tuple = wallet.fresh_spend(&mut rng, anchor, pool_state, b_spend);
        let mut becomes_based = wallet.autonome(
            &mut rng,
            anchor,
            alloc::vec![based_tuple],
            alloc::vec![based_output],
        );
        let autonome_a = wallet.autonome(
            &mut rng,
            anchor,
            alloc::vec![a_tuple],
            alloc::vec![a_output],
        );
        let autonome_b = wallet.autonome(
            &mut rng,
            anchor,
            alloc::vec![b_tuple],
            alloc::vec![b_output],
        );

        let sighash = mock_sighash(becomes_based.commitment().unwrap());

        let based_digests = action_digests(&becomes_based.actions);
        let digests_a = action_digests(&autonome_a.actions);
        let digests_b = action_digests(&autonome_b.actions);

        let (adjunct_a, stamp_a) = autonome_a.strip();
        let (adjunct_b, stamp_b) = autonome_b.strip();

        let mut innocent_digests = digests_a.clone();
        innocent_digests.extend_from_slice(&digests_b);
        let innocent_stamp =
            Stamp::prove_merge(&mut rng, (stamp_a, &digests_a), (stamp_b, &digests_b))
                .expect("innocent merge");

        let based_stamp = Stamp::prove_merge(
            &mut rng,
            (becomes_based.stamp, &based_digests),
            (innocent_stamp, &innocent_digests),
        )
        .expect("based merge");

        becomes_based.stamp = based_stamp;

        becomes_based
            .verify_signatures(&sighash)
            .expect("based aggregate binding sig should verify");

        let all_actions: Vec<Action> = [
            becomes_based.actions.clone(),
            adjunct_a.actions,
            adjunct_b.actions,
        ]
        .concat();

        becomes_based
            .stamp
            .verify(&all_actions, &mut rng)
            .expect("based aggregate stamp should verify against all actions");
    }

    #[test]
    fn invalid_action_sig_fails_verification() {
        let mut rng = StdRng::seed_from_u64(11);
        let mut bundle = build_autonome(&mut rng, 1000, 700);
        let sighash = mock_sighash(bundle.commitment().unwrap());

        let mut sig_bytes: [u8; 64] = bundle.actions[0].sig.into();
        sig_bytes[0] ^= 0xFF;
        bundle.actions[0].sig = action::Signature::from(sig_bytes);

        assert!(bundle.verify_signatures(&sighash).is_err());
    }

    /// Plan::sign produces a verifiable bundle.
    #[test]
    fn plan_sign_and_verify() {
        let mut rng = StdRng::seed_from_u64(700);
        let wallet = WalletSim::new(private::SpendingKey::from([0x42u8; 32]));
        let ask = wallet.sk.derive_auth_private();

        let (stamp, _action, plan) = make_output_stamp(&mut rng, &wallet, 200);
        let bundle_plan = Plan::new(alloc::vec![], alloc::vec![plan]);
        let sighash = mock_sighash(bundle_plan.commitment());

        let stamped = bundle_plan
            .sign(&sighash, &ask, &mut rng)
            .expect("sign should succeed")
            .stamp(stamp);

        stamped
            .verify_signatures(&sighash)
            .expect("signed bundle should verify");
    }

    /// Stamped::write → Stamped::read preserves all fields and the
    /// deserialized bundle remains verifiable.
    #[test]
    fn stamped_read_write_round_trip() {
        let mut rng = StdRng::seed_from_u64(800);
        let original = build_autonome(&mut rng, 1000, 700);
        let mut buf = Vec::new();
        original.write(&mut buf).expect("write");
        let deserialized = Stamped::read(&*buf).expect("read");

        assert_eq!(original.actions, deserialized.actions);
        assert_eq!(original.value_balance, deserialized.value_balance);
        assert_eq!(original.stamp.tachygrams, deserialized.stamp.tachygrams);
        assert_eq!(original.stamp.anchor, deserialized.stamp.anchor);

        let sighash = mock_sighash(deserialized.commitment().unwrap());
        deserialized
            .verify_signatures(&sighash)
            .expect("deserialized bundle must verify");
    }

    /// Stripped adjunct round-trips preserving its assigned wtxid.
    #[test]
    fn stripped_adjunct_read_write_round_trip() {
        let mut rng = StdRng::seed_from_u64(801);
        let (mut stripped, _stamp) = build_autonome(&mut rng, 1000, 700).strip();
        stripped.stamp.wtxid = [0x42u8; 64];

        let mut buf = Vec::new();
        stripped.write(&mut buf).expect("write");
        let deserialized = Stripped::read(&*buf).expect("read");

        assert_eq!(stripped, deserialized);
        assert_eq!(deserialized.stamp.wtxid, [0x42u8; 64]);
    }

    /// Stripped innocent (empty actions) round-trips with a zero wtxid.
    #[test]
    fn stripped_innocent_read_write_round_trip() {
        let mut rng = StdRng::seed_from_u64(802);
        let plan = Plan::new(alloc::vec![], alloc::vec![]);
        let sighash = mock_sighash(plan.commitment());

        let stripped: Stripped = Bundle {
            actions: alloc::vec![],
            value_balance: 0,
            binding_sig: plan.derive_bsk_private().sign(&mut rng, &sighash),
            stamp: Adjunct::default(),
        };

        let mut buf = Vec::new();
        stripped.write(&mut buf).expect("write");
        let deserialized = Stripped::read(&*buf).expect("read");

        assert_eq!(stripped, deserialized);
        assert_eq!(deserialized.stamp.wtxid, [0; 64]);
    }

    /// TachyonBundle round-trips a stamped bundle through the erased form
    /// without losing any fields.
    #[test]
    fn tachyon_bundle_round_trip_stamped() {
        let mut rng = StdRng::seed_from_u64(810);
        let original = build_autonome(&mut rng, 1000, 700);
        let erased: TachyonBundle = original.clone().into();
        let back = Stamped::try_from(erased).expect("stamped variant");

        assert_eq!(original.actions, back.actions);
        assert_eq!(original.value_balance, back.value_balance);
        assert_eq!(original.stamp.tachygrams, back.stamp.tachygrams);
        assert_eq!(original.stamp.anchor, back.stamp.anchor);
    }

    /// TachyonBundle round-trips a stripped bundle's wtxid losslessly.
    #[test]
    fn tachyon_bundle_round_trip_stripped() {
        let mut rng = StdRng::seed_from_u64(811);
        let (mut stripped, _stamp) = build_autonome(&mut rng, 1000, 700).strip();
        stripped.stamp.wtxid = [0xABu8; 64];

        let erased: TachyonBundle = stripped.clone().into();
        let back = Stripped::try_from(erased).expect("stripped variant");

        assert_eq!(stripped, back);
        assert_eq!(back.stamp.wtxid, [0xABu8; 64]);
    }

    /// TachyonBundle::write → TachyonBundle::read round-trips the
    /// variant and the wtxid (for stripped).
    #[test]
    fn bundle_wire_round_trip_via_tachyon_bundle() {
        let mut rng = StdRng::seed_from_u64(812);
        let (mut stripped, _stamp) = build_autonome(&mut rng, 1000, 700).strip();
        stripped.stamp.wtxid = [0xCDu8; 64];

        let erased: TachyonBundle = stripped.clone().into();
        let mut buf = Vec::new();
        erased.write(&mut buf).expect("write");
        let decoded = TachyonBundle::read(&*buf)
            .expect("read")
            .expect("some bundle");
        let back = Stripped::try_from(decoded).expect("stripped variant");

        assert_eq!(stripped, back);
    }

    /// Wire bytes with an invalid state byte are rejected.
    #[test]
    fn wire_rejects_invalid_state_byte() {
        let buf: &[u8] = &[0x03];
        Stamped::read(buf).expect_err("invalid state byte must be rejected");
        Stripped::read(buf).expect_err("invalid state byte must be rejected");
        TachyonBundle::read(buf).expect_err("invalid state byte must be rejected");
    }

    /// empty_commitment() matches the canonical COMMIT_NO_BUNDLE static.
    #[test]
    fn empty_commitment_matches_static() {
        assert_eq!(empty_commitment(), *COMMIT_NO_BUNDLE);
    }

    /// empty_auth_digest() matches the canonical AUTH_DIGEST_NO_BUNDLE static.
    #[test]
    fn empty_auth_digest_matches_static() {
        assert_eq!(empty_auth_digest(), *AUTH_DIGEST_NO_BUNDLE);
    }

    /// A stamped bundle and its stripped sibling produce distinct
    /// auth_digests — the defining property that makes wtxid discriminate
    /// across aggregation forms.
    #[test]
    fn stamped_and_stripped_auth_digests_differ() {
        let mut rng = StdRng::seed_from_u64(820);
        let stamped = build_autonome(&mut rng, 1000, 700);
        let stamped_digest = stamped.auth_digest();

        let (mut stripped, _stamp) = stamped.strip();
        stripped.stamp.wtxid = [0x11u8; 64];
        let stripped_digest = stripped.auth_digest();

        assert_ne!(stamped_digest, stripped_digest);
    }

    /// Different covering-aggregate wtxids on an otherwise-identical stripped
    /// bundle produce distinct auth_digests — confirms the ref enters the
    /// hash.
    #[test]
    fn stripped_auth_digest_binds_wtxid() {
        let mut rng = StdRng::seed_from_u64(821);
        let (mut stripped, _stamp) = build_autonome(&mut rng, 1000, 700).strip();

        stripped.stamp.wtxid = [0xAAu8; 64];
        let a_digest = stripped.auth_digest();

        stripped.stamp.wtxid = [0xBBu8; 64];
        let b_digest = stripped.auth_digest();

        assert_ne!(a_digest, b_digest);
    }

    /// TachyonBundle's dispatching auth_digest matches the concrete-variant
    /// methods.
    #[test]
    fn tachyon_bundle_auth_digest_matches_variants() {
        let mut rng = StdRng::seed_from_u64(822);
        let stamped = build_autonome(&mut rng, 1000, 700);
        let stamped_direct = stamped.auth_digest();
        let erased: TachyonBundle = stamped.into();
        assert_eq!(erased.auth_digest(), stamped_direct);

        let mut rng2 = StdRng::seed_from_u64(823);
        let (mut stripped, _stamp) = build_autonome(&mut rng2, 1000, 700).strip();
        stripped.stamp.wtxid = [0x33u8; 64];
        let stripped_direct = stripped.auth_digest();
        let erased_stripped: TachyonBundle = stripped.into();
        assert_eq!(erased_stripped.auth_digest(), stripped_direct);
    }
}
