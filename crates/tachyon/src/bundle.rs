//! Tachyon transaction bundles.
//!
//! A bundle is parameterized by stamp state `S: StampState`.
//! Actions are constant through state transitions; only the stamp changes.
//!
//! - [`Stamped`] — self-contained bundle with a stamp
//! - [`Stripped`] — stamp removed, depends on an aggregate
//! - `Bundle<Option<Stamp>>` — erased stamp state for mixed contexts

use alloc::vec::Vec;
use core::{error::Error, fmt};

use core2::io::{self, Read, Write};
use ff::Field as _;
use lazy_static::lazy_static;
use mock_ragu::Polynomial;
use pasta_curves::Fp;
use rand_core::{CryptoRng, RngCore};
use zcash_encoding::CompactSize;

use crate::{
    action::{self, Action},
    constants::BUNDLE_COMMITMENT_PERSONALIZATION,
    keys::{private, public},
    primitives::{ActionCommit, ActionDigest, ActionDigestError, Anchor, Tachygram, effect},
    reddsa,
    stamp::{self, Adjunct, Stamp, Unproven, proof::compute_action_acc},
    value,
};

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Stamp {}
    impl Sealed for super::Adjunct {}
    impl Sealed for super::Unproven {}
    impl Sealed for Option<super::Stamp> {}
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

impl From<Stamped> for Bundle<Option<Stamp>> {
    fn from(bundle: Stamped) -> Self {
        Self {
            actions: bundle.actions,
            value_balance: bundle.value_balance,
            binding_sig: bundle.binding_sig,
            stamp: Some(bundle.stamp),
        }
    }
}

impl TryFrom<Bundle<Option<Stamp>>> for Stripped {
    type Error = Stamped;

    fn try_from(bundle: Bundle<Option<Stamp>>) -> Result<Self, Self::Error> {
        match bundle.stamp {
            | None => {
                Ok(Self {
                    actions: bundle.actions,
                    value_balance: bundle.value_balance,
                    binding_sig: bundle.binding_sig,
                    stamp: Adjunct::default(),
                })
            },
            | Some(stamp) => {
                Err(Stamped {
                    actions: bundle.actions,
                    value_balance: bundle.value_balance,
                    binding_sig: bundle.binding_sig,
                    stamp,
                })
            },
        }
    }
}

/// A bundle whose stamp has been stripped — depends on a stamped bundle.
pub type Stripped = Bundle<Adjunct>;

impl From<Stripped> for Bundle<Option<Stamp>> {
    fn from(bundle: Stripped) -> Self {
        Self {
            actions: bundle.actions,
            value_balance: bundle.value_balance,
            binding_sig: bundle.binding_sig,
            stamp: None,
        }
    }
}

impl TryFrom<Bundle<Option<Stamp>>> for Stamped {
    type Error = Stripped;

    fn try_from(bundle: Bundle<Option<Stamp>>) -> Result<Self, Self::Error> {
        match bundle.stamp {
            | Some(stamp) => {
                Ok(Self {
                    actions: bundle.actions,
                    value_balance: bundle.value_balance,
                    binding_sig: bundle.binding_sig,
                    stamp,
                })
            },
            | None => {
                Err(Stripped {
                    actions: bundle.actions,
                    value_balance: bundle.value_balance,
                    binding_sig: bundle.binding_sig,
                    stamp: Adjunct::default(),
                })
            },
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
    #[expect(clippy::expect_used, reason = "todo")]
    pub fn commitment(&self) -> [u8; 64] {
        let roots: Vec<Fp> = self
            .iter_actions(
                |plan| ActionDigest::try_from(plan).expect("don't plan invalid spends"),
                |plan| ActionDigest::try_from(plan).expect("don't plan invalid outputs"),
            )
            .map(Fp::from)
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

/// Read bundle fields: action descriptors, value balance, action sigs,
/// and binding sig.
fn read_bundle<R: Read>(reader: &mut R) -> io::Result<(Vec<Action>, i64, Signature)> {
    let n_actions = CompactSize::read_t::<_, usize>(&mut *reader)?;

    let mut descriptors = Vec::with_capacity(n_actions);
    for _ in 0..n_actions {
        let mut cv_bytes = [0u8; 32];
        reader.read_exact(&mut cv_bytes)?;
        let mut rk_bytes = [0u8; 32];
        reader.read_exact(&mut rk_bytes)?;
        let cv = value::Commitment::from_bytes(cv_bytes).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid value commitment encoding",
            )
        })?;
        let rk = public::ActionVerificationKey::try_from(rk_bytes).map_err(|_err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid action verification key encoding",
            )
        })?;
        descriptors.push((cv, rk));
    }

    let mut vb_bytes = [0u8; 8];
    reader.read_exact(&mut vb_bytes)?;

    let value_balance = i64::from_le_bytes(vb_bytes);

    let mut actions = Vec::with_capacity(n_actions);
    for (cv, rk) in descriptors {
        let mut sig_bytes = [0u8; 64];
        reader.read_exact(&mut sig_bytes)?;
        let sig = action::Signature::from(sig_bytes);
        actions.push(Action { cv, rk, sig });
    }

    let mut binding_sig_bytes = [0u8; 64];
    reader.read_exact(&mut binding_sig_bytes)?;
    let binding_sig = Signature::from(binding_sig_bytes);

    Ok((actions, value_balance, binding_sig))
}

/// Write bundle fields: action descriptors, value balance, action sigs,
/// and binding sig.
fn write_bundle<W: Write>(
    writer: &mut W,
    actions: &[Action],
    value_balance: i64,
    binding_sig: &Signature,
) -> io::Result<()> {
    CompactSize::write(&mut *writer, actions.len())?;

    for action in actions {
        let cv_bytes: [u8; 32] = action.cv.into();
        let rk_bytes: [u8; 32] = action.rk.into();
        writer.write_all(&cv_bytes)?;
        writer.write_all(&rk_bytes)?;
    }

    writer.write_all(&value_balance.to_le_bytes())?;

    for action in actions {
        let sig_bytes: [u8; 64] = action.sig.into();
        writer.write_all(&sig_bytes)?;
    }

    let binding_sig_bytes: [u8; 64] = (*binding_sig).into();
    writer.write_all(&binding_sig_bytes)?;

    Ok(())
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
    /// ## Wire format
    ///
    /// ### Bundle fields
    ///
    /// All bundles contain action count, value balance and binding signature.
    ///
    /// The `stampTachyon` compactsize field should either be
    ///  - single-byte <= 0xFC u8 indexing a stamp on the surrounding block, or
    ///  - three-byte 0xFD prefix u16 specifying size of the attached proof
    ///
    /// | Name                  | Format               | Description                               |
    /// | --------------------- | -------------------- | ----------------------------------------- |
    /// | `nActionsTachyon`     | compactsize          | number of tachyon actions                 |
    /// | `vActionsTachyon`     | 64 * nActionsTachyon | (cv: 32 bytes, rk: 32 bytes)              |
    /// | `valueBalanceTachyon` | int64                | net value of tachyon actions              |
    /// | `vActionSigsTachyon`  | 64 * nActionsTachyon | authorization per action over tx sighash  |
    /// | `bindingSigTachyon`   | 64                   | binding over tx sighash                   |
    /// | `stampTachyon`        | compactsize          | proof size or miner-assigned index        |
    ///
    /// ### Stamp trailer
    ///
    /// If `stampTachyon` is not a single-byte value, a stamp trailer follows.
    ///
    /// | Name               | Format              | Description                       |
    /// | ------------------ | ------------------- | --------------------------------- |
    /// | `anchorTachyon`    | 32                  | pool anchor for this proof        |
    /// | `nTachygrams`      | compactsize         | number of tachygrams              |
    /// | `vTachygrams`      | 32 * nTachygrams    | tachygrams for this proof         |
    /// | `proofTachyon`     | stampTachyon bytes  | a serialized proof, ~23 kilobytes |
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let (actions, value_balance, binding_sig): (Vec<Action>, i64, Signature) =
            read_bundle(&mut reader)?;

        let stamp_size = CompactSize::read_t::<_, usize>(&mut reader)?;
        if stamp_size <= 0xFC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stamped bundle requires stampTachyon >= 253",
            ));
        }

        let anchor = Anchor::read(&mut reader)?;
        let n_tachygrams = CompactSize::read_t::<_, usize>(&mut reader)?;
        let mut tachygrams = Vec::with_capacity(n_tachygrams);
        for _ in 0..n_tachygrams {
            tachygrams.push(Tachygram::read(&mut reader)?);
        }
        let proof = stamp::read_proof_sized(&mut reader, stamp_size)?;

        Ok(Self {
            actions,
            value_balance,
            binding_sig,
            stamp: Stamp {
                tachygrams,
                anchor,
                proof,
            },
        })
    }

    /// Write a stamped bundle in the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_bundle(
            &mut writer,
            &self.actions,
            self.value_balance,
            &self.binding_sig,
        )?;

        CompactSize::write(&mut writer, stamp::proof_serialized_size())?;

        self.stamp.anchor.write(&mut writer)?;
        CompactSize::write(&mut writer, self.stamp.tachygrams.len())?;
        for tg in &self.stamp.tachygrams {
            tg.write(&mut writer)?;
        }
        stamp::write_proof(&mut writer, &self.stamp.proof)
    }
}

impl Stripped {
    /// Read a stripped bundle from the consensus wire format.
    ///
    /// A stripped bundle has `stampTachyon` ≤ 0xFC — a miner-assigned
    /// stamp index with no stamp trailer.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let (actions, value_balance, binding_sig) = read_bundle(&mut reader)?;

        let stamp_size = CompactSize::read_t::<_, usize>(&mut reader)?;
        if stamp_size > 0xFC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stripped bundle requires stampTachyon <= 0xFC",
            ));
        }

        let stamp_index = u8::try_from(stamp_size)
            .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "stamp index overflow"))?;

        Ok(Self {
            actions,
            value_balance,
            binding_sig,
            stamp: Adjunct::new(stamp_index),
        })
    }

    /// Write a stripped bundle in the consensus wire format.
    ///
    /// ### Stamp index
    ///
    /// Miners are responsible for assigning an appropriate stamp index when
    /// assembling a block. Failure to correctly assign an index will prevent
    /// block validation.
    ///
    /// When finalizing a block, a miner will select some transaction order and
    /// thus determine the position of each transaction containing a stamp.
    /// Before serialization, stripped adjuncts should be provided an index
    /// referring to their associated aggregate by its position among the stamps
    /// in block order (only counting stamped bundles; this is not a 0-indexed
    /// position among all transactions).
    ///
    /// Use of a single-byte compactsize value for this purpose technically
    /// requires aggregate stamps to be located among the first 253 stamps in
    /// the block. Given the present block limit of 2MB, this is acceptable.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_bundle(
            &mut writer,
            &self.actions,
            self.value_balance,
            &self.binding_sig,
        )?;

        let stamp_index = self.stamp.get_index().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "stamp_index must be assigned before serialization",
            )
        })?;

        CompactSize::write(&mut writer, usize::from(stamp_index))
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
        note::{self, Note},
        primitives::{BlockHeight, PoolCommit},
        stamp::Stamp,
        value,
    };

    /// Normally, data from other parts of the transaction is included in the
    /// sighash, not just the bundle commitment.
    fn mock_sighash(bundle_digest: [u8; 64]) -> [u8; 32] {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"pretend sighash")
            .to_state()
            .update(&bundle_digest)
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    fn make_output_stamp(
        rng: &mut (impl RngCore + CryptoRng),
        sk: &private::SpendingKey,
        value_amount: u64,
    ) -> (Stamp, Action, action::Plan<effect::Output>) {
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(value_amount),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
        };
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

    fn build_autonome(
        rng: &mut (impl RngCore + CryptoRng),
        spend_value: u64,
        output_value: u64,
    ) -> Stamped {
        let sk = private::SpendingKey::from([0x42u8; 32]);

        let spend_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(spend_value),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
        };
        let output_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(output_value),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
        };

        let spend_rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let output_rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let theta_spend = ActionEntropy::random(&mut *rng);
        let theta_output = ActionEntropy::random(&mut *rng);

        let spend_plan = action::Plan::output(spend_note, theta_spend, spend_rcv);
        let output_plan = action::Plan::output(output_note, theta_output, output_rcv);

        let bundle_plan = Plan::new(alloc::vec![], alloc::vec![spend_plan, output_plan]);
        let sighash = mock_sighash(bundle_plan.commitment());

        let spend_alpha = theta_spend.randomizer::<effect::Output>(&spend_note.commitment());
        let output_alpha = theta_output.randomizer::<effect::Output>(&output_note.commitment());

        let spend_rsk = private::ActionSigningKey::new(&spend_alpha);
        let output_rsk = private::ActionSigningKey::new(&output_alpha);

        let spend_action = Action {
            cv: spend_plan.cv(),
            rk: spend_plan.rk,
            sig: spend_rsk.sign(&mut *rng, &sighash),
        };
        let output_action = Action {
            cv: output_plan.cv(),
            rk: output_plan.rk,
            sig: output_rsk.sign(&mut *rng, &sighash),
        };

        let spend_stamp = Stamp::prove_output(
            &mut *rng,
            spend_rcv,
            spend_alpha,
            spend_note,
            Anchor(
                BlockHeight(0),
                PoolCommit(Polynomial::default().commit(Fp::ZERO)),
            ),
        )
        .expect("prove_output (spend-value)");

        let output_stamp = Stamp::prove_output(
            &mut *rng,
            output_rcv,
            output_alpha,
            output_note,
            Anchor(
                BlockHeight(0),
                PoolCommit(Polynomial::default().commit(Fp::ZERO)),
            ),
        )
        .expect("prove_output (output-value)");

        let spend_digests = alloc::vec![Fp::from(ActionDigest::try_from(&spend_action).unwrap(),)];
        let output_digests =
            alloc::vec![Fp::from(ActionDigest::try_from(&output_action).unwrap(),)];
        let stamp = Stamp::prove_merge(
            &mut *rng,
            spend_stamp,
            &spend_digests,
            output_stamp,
            &output_digests,
        )
        .expect("prove_merge");

        let bundle: Stamped = Bundle {
            actions: alloc::vec![spend_action, output_action],
            value_balance: bundle_plan.value_balance(),
            binding_sig: bundle_plan.derive_bsk_private().sign(&mut *rng, &sighash),
            stamp,
        };

        bundle
            .verify_signatures(&sighash)
            .expect("autonome signatures should verify");
        bundle
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
    #[test]
    fn plan_commitment_matches_bundle_commitment() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = private::SpendingKey::from([0x42u8; 32]);

        let (stamp, output_action, output_plan) = make_output_stamp(&mut rng, &sk, 200);

        let bundle_plan = Plan::new(alloc::vec![], alloc::vec![output_plan]);
        let sighash = mock_sighash(bundle_plan.commitment());

        let output_rsk = private::ActionSigningKey::new(
            &ActionEntropy::random(&mut rng).randomizer::<effect::Output>(
                &Note {
                    pk: sk.derive_payment_key(),
                    value: note::Value::from(200u64),
                    psi: note::NullifierTrapdoor::from(Fp::ZERO),
                    rcm: note::CommitmentTrapdoor::from(Fp::ZERO),
                }
                .commitment(),
            ),
        );
        let signed_action = Action {
            cv: output_action.cv,
            rk: output_action.rk,
            sig: output_rsk.sign(&mut rng, &sighash),
        };

        let bundle: Stamped = Bundle {
            actions: alloc::vec![signed_action],
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

    fn action_digests(actions: &[Action]) -> Vec<Fp> {
        actions
            .iter()
            .map(|action| Fp::from(ActionDigest::try_from(action).unwrap()))
            .collect()
    }

    #[test]
    fn innocent_aggregate_from_two_autonomes() {
        let mut rng = StdRng::seed_from_u64(0xCAFE);

        let autonome_a = build_autonome(&mut rng, 1000, 700);
        let autonome_b = build_autonome(&mut rng, 500, 200);

        let digests_a = action_digests(&autonome_a.actions);
        let digests_b = action_digests(&autonome_b.actions);
        let (adjunct_a, stamp_a) = autonome_a.strip();
        let (adjunct_b, stamp_b) = autonome_b.strip();

        let innocent: Stamped = {
            let innocent_plan = Plan::new(alloc::vec![], alloc::vec![]);
            let innocent_sighash = mock_sighash(innocent_plan.commitment());

            let stamp = Stamp::prove_merge(&mut rng, stamp_a, &digests_a, stamp_b, &digests_b)
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

        let mut becomes_based = build_autonome(&mut rng, 800, 400);
        let autonome_a = build_autonome(&mut rng, 1000, 700);
        let autonome_b = build_autonome(&mut rng, 500, 200);

        let sighash = mock_sighash(becomes_based.commitment().unwrap());

        let based_digests = action_digests(&becomes_based.actions);
        let digests_a = action_digests(&autonome_a.actions);
        let digests_b = action_digests(&autonome_b.actions);

        let (adjunct_a, stamp_a) = autonome_a.strip();
        let (adjunct_b, stamp_b) = autonome_b.strip();

        let mut innocent_digests = digests_a.clone();
        innocent_digests.extend_from_slice(&digests_b);
        let innocent_stamp = Stamp::prove_merge(&mut rng, stamp_a, &digests_a, stamp_b, &digests_b)
            .expect("innocent merge");

        let based_stamp = Stamp::prove_merge(
            &mut rng,
            becomes_based.stamp,
            &based_digests,
            innocent_stamp,
            &innocent_digests,
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
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();

        let (stamp_a, action_a, plan_a) = make_output_stamp(&mut rng, &sk, 200);
        let (stamp_b, action_b, plan_b) = make_output_stamp(&mut rng, &sk, 300);

        let bundle_plan = Plan::new(alloc::vec![], alloc::vec![plan_a, plan_b]);
        let sighash = mock_sighash(bundle_plan.commitment());

        let unproven = bundle_plan
            .sign(&sighash, &ask, &mut rng)
            .expect("sign should succeed");

        let digests_a = action_digests(&[action_a]);
        let digests_b = action_digests(&[action_b]);
        let stamp = Stamp::prove_merge(&mut rng, stamp_a, &digests_a, stamp_b, &digests_b)
            .expect("prove_merge");
        let stamped = unproven.stamp(stamp);

        stamped
            .verify_signatures(&sighash)
            .expect("signed bundle should verify");
    }

    /// Plan::stamp_plan → stamp::Plan::prove → verify end-to-end.
    #[test]
    fn plan_stamp_plan_produces_valid_stamp() {
        let mut rng = StdRng::seed_from_u64(701);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();

        let note_a = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(200u64),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
        };
        let note_b = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(300u64),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
        };

        let rcv_a = value::CommitmentTrapdoor::random(&mut rng);
        let rcv_b = value::CommitmentTrapdoor::random(&mut rng);
        let theta_a = ActionEntropy::random(&mut rng);
        let theta_b = ActionEntropy::random(&mut rng);

        let plan_a = action::Plan::output(note_a, theta_a, rcv_a);
        let plan_b = action::Plan::output(note_b, theta_b, rcv_b);

        let bundle_plan = Plan::new(alloc::vec![], alloc::vec![plan_a, plan_b]);
        let anchor = Anchor(
            BlockHeight(0),
            PoolCommit(Polynomial::default().commit(Fp::ZERO)),
        );

        let stamp_plan = bundle_plan.stamp_plan(anchor);
        let stamp = stamp_plan
            .prove(&mut rng, &pak, alloc::vec![])
            .expect("stamp plan prove");

        // Build actions to verify against
        let actions: Vec<Action> = bundle_plan
            .iter_actions(
                |plan| {
                    Action {
                        cv: plan.cv(),
                        rk: plan.rk,
                        sig: action::Signature::from([0u8; 64]),
                    }
                },
                |plan| {
                    Action {
                        cv: plan.cv(),
                        rk: plan.rk,
                        sig: action::Signature::from([0u8; 64]),
                    }
                },
            )
            .collect();

        stamp
            .verify(&actions, &mut rng)
            .expect("stamp_plan-produced stamp should verify");
    }

    /// Stamped::write → Stamped::read preserves all fields.
    #[test]
    fn stamped_read_write_round_trip() {
        let mut rng = StdRng::seed_from_u64(800);
        let original = build_autonome(&mut rng, 1000, 700);

        let mut buf = Vec::new();
        original.write(&mut buf).expect("write should succeed");

        let deserialized = Stamped::read(&*buf).expect("read should succeed");

        assert_eq!(original.actions.len(), deserialized.actions.len());
        assert_eq!(original.value_balance, deserialized.value_balance);
        assert_eq!(
            original.stamp.tachygrams.len(),
            deserialized.stamp.tachygrams.len()
        );
        assert_eq!(original.stamp.anchor, deserialized.stamp.anchor);

        // Verify the deserialized bundle is still valid
        let sighash = mock_sighash(deserialized.commitment().unwrap());
        deserialized
            .verify_signatures(&sighash)
            .expect("deserialized bundle should verify");
    }

    /// Stripped::write → Stripped::read preserves all fields including adjunct
    /// index.
    #[test]
    fn stripped_read_write_round_trip() {
        let mut rng = StdRng::seed_from_u64(801);
        let autonome = build_autonome(&mut rng, 1000, 700);
        let (mut stripped, _stamp) = autonome.strip();
        stripped.stamp.set_index(42);

        let mut buf = Vec::new();
        stripped.write(&mut buf).expect("write should succeed");

        let deserialized = Stripped::read(&*buf).expect("read should succeed");

        assert_eq!(stripped.actions.len(), deserialized.actions.len());
        assert_eq!(stripped.value_balance, deserialized.value_balance);
        assert_eq!(
            deserialized.stamp.get_index(),
            Some(42),
            "adjunct index must survive round-trip"
        );
    }

    /// Stripped::write fails when the adjunct index hasn't been assigned.
    #[test]
    fn stripped_write_rejects_unset_index() {
        let mut rng = StdRng::seed_from_u64(802);
        let autonome = build_autonome(&mut rng, 1000, 700);
        let (stripped, _stamp) = autonome.strip();

        // Adjunct index is None by default after strip
        let mut buf = Vec::new();
        let result = stripped.write(&mut buf);
        assert!(result.is_err(), "write must fail when stamp_index is unset");
    }
}
