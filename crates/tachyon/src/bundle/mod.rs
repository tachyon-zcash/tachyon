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
    primitives::{ActionCommit, ActionDigest, ActionDigestError, Anchor, Tachygram, effect},
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
    #[must_use]
    pub fn stamp_plan(&self, anchor: Anchor) -> stamp::Plan {
        let spends = self
            .spends
            .iter()
            .map(|plan| {
                let alpha = plan.theta.randomizer(&plan.note.commitment());
                ((plan.cv(), plan.rk), (alpha, plan.note, plan.rcv))
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
        usize::try_from(serialization::read_compactsize(&mut reader)?).map_err(io::Error::other)?;

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
        u64::try_from(actions.len()).map_err(io::Error::other)?,
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
mod tests;
