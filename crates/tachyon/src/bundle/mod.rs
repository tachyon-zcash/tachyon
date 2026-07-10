//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by bundle state `S: BundleState`.
//! Actions are constant through state transitions; only the stamp changes.
//!
//! - `Bundle<ProofStamp>` — self-contained bundle with a proof stamp
//! - `Bundle<PointerStamp>` — proof stamp replaced by a pointer stamp naming
//!   the covering aggregate
//! - [`TachyonBundle`] — enum of the on-wire forms for mixed contexts
//!
//! # Consensus wire format
//!
//! The first byte `tachyonBundleState` selects one of three bundle states:
//!
//! | value         | state         | bundle contents                       |
//! | ------------- | ------------- | ------------------------------------- |
//! | `0b0000_0000` | non-tachyon   | no bundle                             |
//! | `0b0000_0001` | proof stamp   | bundle with anchor, tachygrams, proof |
//! | `0b0000_0010` | pointer stamp | bundle with aggregate's wtxid         |
//! | `...`         | *reserved*    | *n/a*                                 |
//!
//! Any other byte is invalid. Pointer-stamped innocents and adjuncts share
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
//! ### Proof stamp
//!
//! When `tachyonBundleState == 1`, the bundle carries a proof stamp.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `hActionsTachyon`     | 32 bytes             | BLAKE2b digest of the covered actions    |
//! | `anchorTachyon`       | 32 bytes             | pool state reference                     |
//! | `nTachygrams`         | compactsize          | number of tachygrams                     |
//! | `vTachygrams`         | 32 * nTachygrams     | tachygrams for this proof                |
//! | `proofTachyon`        | PROOF_SIZE blob      | serialized proof of fixed size           |
//!
//! ## Pointer stamp
//!
//! When `tachyonBundleState == 2`, the bundle carries a pointer stamp.
//!
//! | Name                  | Format               | Description                              |
//! | --------------------- | -------------------- | ---------------------------------------- |
//! | `tachyonAggregateId`  | 64 bytes             | wtxid of the relevant aggregate          |
//!
//! The transaction `auth_digest` contribution commits either stamp as a
//! 64-byte wtxid-shaped value: the pointer stamp's `wtxid` directly, or
//! `hActionsTachyon || stamp_data_digest` for a proof stamp.

use alloc::vec::Vec;
use core::ops;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, From, IsVariant, PartialEq, TryInto};
use rand_core::{CryptoRng, RngCore};

use crate::{
    action::{self, Action},
    digest::blake2b,
    keys::{private, public},
    note,
    primitives::{ActionDigestError, Anchor, effect},
    reddsa, serialization,
    stamp::{self, PointerStamp, ProofStamp, StampState, Unproven},
};

/// The `tachyonBundleState` wire byte. See the module-level wire format
/// documentation for its role.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
#[repr(u8)]
pub enum StateByte {
    /// No bundle.
    NoBundle = 0b0000_0000u8,
    /// Proof stamped bundle.
    ProofStamped = 0b0000_0001u8,
    /// Pointer stamped bundle.
    PointerStamped = 0b0000_0010u8,
}

impl StateByte {
    pub(super) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        match u8::from_le_bytes(byte) {
            0b0000_0000u8 => Ok(Self::NoBundle),
            0b0000_0001u8 => Ok(Self::ProofStamped),
            0b0000_0010u8 => Ok(Self::PointerStamped),
            _other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid bundle state",
            )),
        }
    }

    pub(super) fn write<W: Write>(self, mut writer: W) -> io::Result<()> {
        #[expect(clippy::as_conversions, reason = "repr u8")]
        writer.write_all(&(self as u8).to_le_bytes())
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Unproven {}
    impl Sealed for super::ProofStamp {}
    impl Sealed for super::PointerStamp {}
}

/// Sealed trait constraining bundle state types.
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
pub trait BundleState: sealed::Sealed {}

impl<T: sealed::Sealed> BundleState for T {}

/// A Tachyon transaction bundle parameterized by bundle state `S`.
#[derive(Clone, Debug, PartialEq, TotalEq)]
pub struct Bundle<S: BundleState + ?Sized> {
    /// Actions (cv, rk, sig).
    pub actions: Vec<Action>,

    /// Net value of spends minus outputs (plaintext integer).
    pub value_balance: i64,

    /// Binding signature over the transaction sighash.
    pub binding_sig: Signature,

    /// Bundle state: `Unproven`, `ProofStamp`, or `PointerStamp`.
    pub stamp: S,
}

impl<S: BundleState + ?Sized> Bundle<S> {
    /// Collect the descriptors of all actions in the bundle.
    #[must_use]
    pub fn descriptors(&self) -> Vec<action::Descriptor> {
        // Do NOT sort here: a constructed bundle should already be canonical.
        self.actions.iter().map(Action::descriptor).collect()
    }

    /// Digest the bundle's effecting data.
    ///
    /// This contributes to the transaction sighash. The stamp is excluded
    /// because it is considered authorizing data, and is malleable during
    /// aggregation.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let descriptors: Vec<[u8; 64]> = self
            .descriptors()
            .into_iter()
            .map(<[u8; 64]>::from)
            .collect();

        // The bundle's actions should already be sorted by construction.
        debug_assert!(
            descriptors.is_sorted(),
            "bundle actions must be canonically sorted"
        );

        blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&descriptors),
            self.value_balance,
        )
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
    #[display("plan rk {_0:?} does not match")]
    RkMismatch(#[error(not(source))] reddsa::VerificationKeyBytes<reddsa::ActionAuth>),
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

    /// Collect and sort the descriptors of all actions in the plan.
    #[must_use]
    pub fn descriptors(&self) -> Vec<action::Descriptor> {
        let mut desc = self
            .iter_actions(action::Plan::descriptor, action::Plan::descriptor)
            .collect::<Vec<action::Descriptor>>();
        desc.sort_unstable();
        desc
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
    /// See [`Bundle::commitment`].
    pub fn commitment(&self) -> Result<[u8; 32], CommitError> {
        let desc_bytes: Vec<[u8; 64]> = self
            .descriptors()
            .into_iter()
            .map(<[u8; 64]>::from)
            .collect();

        Ok(blake2b::bundle_commitment(
            &blake2b::action_descriptor_digest(&desc_bytes),
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
                (plan.descriptor(), alpha, plan.note, plan.rcv)
            })
            .collect();

        let outputs = self
            .outputs
            .iter()
            .map(|plan| {
                let alpha = plan.theta.randomizer(plan.note.commitment());
                (plan.descriptor(), alpha, plan.note, plan.rcv)
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
    /// signature. The resulting actions are canonically sorted so that the
    /// bundle matches its commitment's descriptor order.
    ///
    /// The result is a `Bundle<Unproven>` — combine with a [`ProofStamp`]
    /// via [`Bundle::stamp`] to produce a `Bundle<ProofStamp>`.
    pub fn sign<RNG: RngCore + CryptoRng>(
        &self,
        sighash: &[u8; 32],
        ask: &private::SpendAuthorizingKey,
        rng: &mut RNG,
    ) -> Result<Bundle<Unproven>, SignError> {
        let n_actions = self.spends.len() + self.outputs.len();
        let mut authorized = Vec::with_capacity(n_actions);

        for plan in &self.spends {
            let cm = plan.note.commitment();
            let alpha = plan.theta.randomizer::<effect::Spend>(cm);
            let rsk = ask.derive_action_private(&alpha);
            if rsk.derive_action_public() != plan.rk {
                return Err(SignError::RkMismatch(plan.rk.0.into()));
            }
            authorized.push(Action {
                cv: plan.cv(),
                rk: plan.rk,
                sig: rsk.sign(rng, sighash),
            });
        }

        for plan in &self.outputs {
            let cm = plan.note.commitment();
            let alpha = plan.theta.randomizer::<effect::Output>(cm);
            let rsk = private::ActionSigningKey::new(&alpha);
            if rsk.derive_action_public() != plan.rk {
                return Err(SignError::RkMismatch(plan.rk.0.into()));
            }
            authorized.push(Action {
                cv: plan.cv(),
                rk: plan.rk,
                sig: rsk.sign(rng, sighash),
            });
        }

        authorized.sort_unstable();

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

    /// Apply externally-produced signatures.
    ///
    /// Validates each signature against the action's rk and the sighash.
    /// Derives cv from each plan and produces the binding signature. The
    /// resulting actions are canonically sorted; each signature stays paired
    /// with its descriptor, so sorting preserves the pairing.
    pub fn apply_signatures<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
        sighash: &[u8; 32],
        sigs: Vec<action::Signature>,
    ) -> Result<Bundle<Unproven>, SignError> {
        let n_actions = self.spends.len() + self.outputs.len();
        if sigs.len() != n_actions {
            return Err(SignError::SigCountMismatch(n_actions));
        }

        let authorized = self
            .descriptors()
            .into_iter()
            .zip(sigs)
            .map(|(desc, sig)| {
                desc.rk
                    .verify(sighash, &sig)
                    .map_err(|_err| SignError::InvalidActionSignature(sig))?;
                Ok(Action::from_parts(desc, sig))
            })
            .collect::<Result<Vec<Action>, SignError>>()?;

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
    /// Attach a proof stamp, producing a `Bundle<ProofStamp>`.
    #[must_use]
    pub fn stamp(self, stamp: ProofStamp) -> Bundle<ProofStamp> {
        Bundle {
            actions: self.actions,
            value_balance: self.value_balance,
            binding_sig: self.binding_sig,
            stamp,
        }
    }
}

impl Bundle<ProofStamp> {
    /// Replace the stamp with a wtixd pointer to a covering aggregate.
    #[must_use]
    pub fn strip(self, wtxid: PointerStamp) -> Bundle<PointerStamp> {
        Bundle {
            actions: self.actions,
            value_balance: self.value_balance,
            binding_sig: self.binding_sig,
            stamp: wtxid,
        }
    }

    /// Confirm published coverage without verifying the proof: reconstruct
    /// the covered-actions digest from this bundle's actions plus every
    /// adjunct's and check it against the carried `hActionsTachyon`.
    /// Adjuncts may be in any stamp state, mixed freely. Assistive, not
    /// soundness.
    #[must_use]
    pub fn covers(&self, adjuncts: &[&Bundle<dyn StampState>]) -> bool {
        let own_descs = self.actions.iter().map(Action::descriptor);
        let other_descs = adjuncts
            .iter()
            .flat_map(|adjunct| adjunct.actions.iter())
            .map(Action::descriptor);

        self.stamp.covers(
            &own_descs
                .chain(other_descs)
                .collect::<Vec<action::Descriptor>>(),
        )
    }

    /// Check if this bundle is an aggregate, by computing the digest of its
    /// owned actions and comparing to its stamp's `hActionsTachyon`.
    #[must_use]
    pub fn is_aggregate(&self) -> bool {
        let desc_bytes: Vec<[u8; 64]> = self
            .descriptors()
            .into_iter()
            .map(<[u8; 64]>::from)
            .collect();
        blake2b::action_descriptor_digest(&desc_bytes) == self.stamp.covered_actions
    }
}

impl<S: StampState> Bundle<S> {
    /// Read a stamped bundle in state `S` from the consensus wire format.
    ///
    /// See the module-level wire format documentation.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let head = StateByte::read(&mut reader)?;

        if head != S::state_byte() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected tachyonBundleState",
            ));
        }

        Self::read_body(reader)
    }

    /// Read everything after the `tachyonBundleState` byte: value balance,
    /// action descriptors, action sigs, binding sig, and the stamp trailer.
    fn read_body<R: Read>(mut reader: R) -> io::Result<Self> {
        let value_balance = i64::from_le_bytes({
            let mut vb_bytes = [0u8; 8];
            reader.read_exact(&mut vb_bytes)?;
            vb_bytes
        });

        // `n_actions` is attacker-controlled up to MAX_COMPACT_SIZE (2^25), so
        // do not pre-allocate vector capacity. vector reads are ASSUMED to hit
        // invalid data or EOF before significant problems occur.
        // TODO: assert a reasonable maximum, to allow pre-allocation?
        let n_actions =
            usize::try_from(serialization::read_compactsize(&mut reader)?).map_err(|_err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "actions vector length exceeds usize",
                )
            })?;

        let mut descriptors: Vec<action::Descriptor> = Vec::new();
        for _ in 0..n_actions {
            descriptors.push(action::Descriptor::read(&mut reader)?);
        }

        if !descriptors.is_sorted() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "actions are not canonically sorted",
            ));
        }

        let mut signatures: Vec<action::Signature> = Vec::new();
        for _ in 0..n_actions {
            signatures.push(action::Signature::read(&mut reader)?);
        }

        let actions: Vec<Action> = descriptors
            .into_iter()
            .zip(signatures)
            .map(|(desc, sig)| Action::from_parts(desc, sig))
            .collect();

        let binding_sig = Signature::read(&mut reader)?;

        let stamp = S::read(&mut reader)?;

        Ok(Self {
            actions,
            value_balance,
            binding_sig,
            stamp,
        })
    }

    /// Write the bundle in the consensus wire format: the
    /// `tachyonBundleState` byte for `S`, the bundle body, and the stamp.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        S::state_byte().write(&mut writer)?;

        writer.write_all(&self.value_balance.to_le_bytes())?;

        let n_actions = u64::try_from(self.actions.len()).map_err(|_err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "actions vector length exceeds u64",
            )
        })?;
        serialization::write_compactsize(&mut writer, n_actions)?;

        for action in &self.actions {
            action.descriptor().write(&mut writer)?;
        }
        for action in &self.actions {
            action.sig.write(&mut writer)?;
        }

        self.binding_sig.write(&mut writer)?;

        self.stamp.write(&mut writer)
    }

    /// Tachyon's contribution to the transaction `auth_digest`.
    ///
    /// Commits the action descriptor digest, the action signatures, the
    /// binding signature, and the stamp's digest. See
    /// [`blake2b::bundle_auth_digest`].
    #[must_use]
    pub fn auth_digest(&self) -> [u8; 32] {
        let descriptors: Vec<[u8; 64]> = self
            .descriptors()
            .into_iter()
            .map(<[u8; 64]>::from)
            .collect();

        // The bundle's actions should already be sorted by construction.
        debug_assert!(
            descriptors.is_sorted(),
            "bundle actions must be canonically sorted"
        );
        let action_digest = blake2b::action_descriptor_digest(&descriptors);

        let action_sigs: Vec<[u8; 64]> = self.actions.iter().map(|act| act.sig.into()).collect();
        let binding_sig: [u8; 64] = self.binding_sig.into();

        blake2b::bundle_auth_digest(
            &action_digest,
            &action_sigs,
            &binding_sig,
            &self.stamp.stamp_digest(),
        )
    }
}

/// A Tachyon bundle in any of its on-wire states: absent, stamped, or stripped.
/// Provided for consumers to switch over any form.
///
/// The `Unproven` intermediate state is outside this enum because it has no
/// wire representation.
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
#[derive(Clone, Debug, From, IsVariant, TryInto)]
pub enum TachyonBundle {
    /// No bundle.
    NoBundle,
    /// A bundle with its own stamp (autonome or aggregate).
    Proven(Bundle<ProofStamp>),
    /// A bundle whose stamp has been stripped; carries a reference to the
    /// covering aggregate via its [`PointerStamp`].
    Adjunct(Bundle<PointerStamp>),
}

impl TachyonBundle {
    /// Read any Tachyon bundle from the consensus wire format, dispatching
    /// on the `tachyonBundleState` byte.
    ///
    /// Decodes `0x00` (non-tachyon) as [`Self::NoBundle`], `0x01` as a
    /// proof-stamped bundle, and `0x02` as a pointer-stamped bundle;
    /// rejects any other byte.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let state = StateByte::read(&mut reader)?;

        Ok(match state {
            StateByte::NoBundle => Self::NoBundle,
            StateByte::ProofStamped => Self::Proven(Bundle::read_body(&mut reader)?),
            StateByte::PointerStamped => Self::Adjunct(Bundle::read_body(&mut reader)?),
        })
    }

    /// Write any Tachyon bundle in the consensus wire format, dispatching on
    /// the variant.
    #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        match *self {
            Self::NoBundle => StateByte::NoBundle.write(writer),
            Self::Proven(ref stamped) => stamped.write(writer),
            Self::Adjunct(ref stripped) => stripped.write(writer),
        }
    }

    /// Tachyon's contribution to the transaction `auth_digest`, dispatching
    /// on the variant. See [`Bundle::auth_digest`].
    #[must_use]
    #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
    pub fn auth_digest(&self) -> [u8; 32] {
        match *self {
            Self::NoBundle => *blake2b::AUTH_DIGEST_NO_BUNDLE,
            Self::Proven(ref stamped) => stamped.auth_digest(),
            Self::Adjunct(ref stripped) => stripped.auth_digest(),
        }
    }

    /// Tachyon's contribution to the transaction sighash (txid side).
    ///
    /// Dispatches on the variant to [`Bundle::commitment`], which commits the
    /// owned actions' descriptors and the value balance; a `NoBundle`
    /// contributes the fixed `COMMIT_NO_BUNDLE` sentinel. The stamp and the
    /// signatures are excluded (they belong to the `auth_digest`).
    #[must_use]
    #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
    pub fn commitment(&self) -> [u8; 32] {
        match *self {
            Self::NoBundle => *blake2b::COMMIT_NO_BUNDLE,
            Self::Proven(ref stamped) => stamped.commitment(),
            Self::Adjunct(ref stripped) => stripped.commitment(),
        }
    }

    /// Check if this bundle is an aggregate, by computing the digest of its
    /// owned actions and comparing to its stamp's `hActionsTachyon` if present.
    #[must_use]
    #[expect(clippy::ref_patterns, reason = "match needs explicit ref")]
    pub fn is_aggregate(&self) -> bool {
        match *self {
            Self::NoBundle => false,
            Self::Proven(ref stamped) => stamped.is_aggregate(),
            Self::Adjunct(ref _stripped) => false,
        }
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

impl Signature {
    /// Read a binding signature from the consensus wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let sig = serialization::read_binding_sig(&mut reader)?;
        Ok(Self(sig))
    }

    /// Write a binding signature to the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_binding_sig(&mut writer, &self.0)?;
        Ok(())
    }
}

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

#[cfg(test)]
mod tests;
