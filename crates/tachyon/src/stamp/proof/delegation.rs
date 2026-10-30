//! Prove a fusable range of a note's per-epoch nullifiers.
//!
//! Three steps. [`NoteSeed`] certifies the note's commitment and master
//! key; [`NullifierDerive`] consumes that seed and exports one whole window;
//! and [`NullifierFuse`] concatenates adjacent windows.
//!
//! All headers are wallet-only, and no key material rides the exported
//! [`NoteNullifiers`].

extern crate alloc;
use ragu::{
    Cycle as _, Encoded, Header, Index, PoseidonPermutation as _, Step, StepCtx,
    pasta::{EpAffine, Fp, Pasta, PoseidonFp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_pcd::pasta::baked;
use ragu_primitives::{
    Element, GadgetExt as _,
    poseidon::{Sponge, SpongeState},
    vec::FixedVec,
};
use udon::{curve::Affine as _, field::Field as _};

pub use crate::stamp::headers::delegation::{NoteNullifiers, NoteSecret};
use crate::{
    constants::{EPOCH_MAX, MAX_MONEY},
    digest::poseidon,
    gadgets::arithmetic as circuit,
    keys::{NoteMasterKey, PaymentKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH},
    primitives::{EpochIndex, NfSeqPoly},
    relations::enforce::{
        bind_poly_handle, enforce_poly_product, indexed_member_factor, poly_handle_limbs,
    },
    value,
};

/// Certify a note's commitment and master key.
///
/// Seed step. Witnesses the note's value and trapdoors and its proof
/// authorizing key. The note's payment key is derived from `pak`, which pins
/// `nk`; `mk` is derived from `nk` and `psi`; and `cm` commits to the
/// assembled note. `nk` never leaves the step; only `pk`, which
/// preimage-hides it, enters `cm`.
///
/// # Soundness
///
/// A seed can invent a note, so `cm` closes downstream, at
/// [`SpendableInit`](super::spendable::SpendableInit) and
/// [`SpendBind`](super::spend::SpendBind). What this step establishes is
/// the pairing: `mk` is *this* `cm`'s master key.
#[derive(Debug)]
pub struct NoteSeed;

impl Step for NoteSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NoteSecret;
    type Right = ();
    type Shared = ();
    /// `(value, psi, rcm, pak)`
    type Witness<'source> = (
        value::Positive,
        nullifier::Trapdoor,
        note::CommitmentTrapdoor,
        ProofAuthorizingKey,
    );

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let value = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(u64::from(data.0))),
        )?;
        circuit::bounded::<D, 51>(ctx.dr, &value, MAX_MONEY)?;
        let psi = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.1)),
        )?;
        let rcm = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.2)),
        )?;
        rcm.clone().enforce_nonzero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("NoteSeed: commitment trapdoor is zero".into())
        })?;
        let nk = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.3.nk)),
        )?;
        let ak_assignment = D::try_just(|| {
            let bytes: [u8; 32] = witness.as_ref().take().3.ak.0.into();
            EpAffine::from_bytes(bytes)
                .ok_or_else(|| ragu_core::Error::InvalidWitness("invalid ak encoding".into()))
        })?;
        let ak = crate::gadgets::point::CurvePoint::alloc(ctx.dr, &mut (), ak_assignment)?;
        let pk = poseidon::payment_key_circuit(ctx.dr, &[ak.x, ak.y, nk.clone()])?;
        let state = SpongeState::from_elements(FixedVec::from_fn(|index| {
            Element::constant(
                ctx.dr,
                if index == PoseidonFp::RATE {
                    Fp::from_u128(u128::from_le_bytes(*b"Tachyon-NfMaster"))
                } else {
                    Fp::ZERO
                },
            )
        }));
        let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(baked()));
        sponge.absorb(ctx.dr, &psi)?;
        sponge.absorb(ctx.dr, &nk)?;
        let mk = sponge.squeeze(ctx.dr)?;
        let cm = poseidon::note_commitment_circuit(
            ctx.dr,
            &[rcm.clone(), pk.clone(), value.clone(), psi.clone()],
        )?;
        let output = D::just(|| {
            let (note_value, note_psi, note_rcm, _) = witness.take();
            let note = Note {
                pk: PaymentKey::from(*pk.value().take()),
                value: note_value,
                psi: note_psi,
                rcm: note_rcm,
            };
            (
                note::Commitment::from(*cm.value().take()),
                note,
                NoteMasterKey(*mk.value().take()),
            )
        });
        let fields = crate::stamp::headers::delegation::NoteSecretOutput {
            cm: (cm).into(),
            note: crate::gadgets::note::NoteGadget {
                rcm: (rcm).into(),
                pk: (pk).into(),
                value: (value).into(),
                psi: (psi).into(),
            },
            mk: (mk).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
    }
}

/// Derive one window of nullifiers and export it as a
/// [`NoteNullifiers`].
///
/// `Left = NoteSeed`. Witnesses the window's start epoch (constrained
/// group-aligned, $w \bmod r = 0$ for $r$ the sponge rate `PoseidonFp::RATE`)
/// and the window sequence. Runs one `Tachyon-NfDerive` sponge per group over
/// $(\mathsf{mk}, w)$, each absorbing two elements and squeezing $r$
/// nullifiers for one permutation, then binds the sequence to the window's
/// members by a single opening at a free $z$ against their driver-computed
/// product.
///
/// # Soundness
///
/// `mk` is threaded from the left header, so it is the note's genuine master
/// key by PCD soundness. The opening's only free operand is the window
/// sequence, committed before $z$ exists.
///
/// `epoch_start` is a free witness constrained group-aligned, pinned by the
/// header it produces: it is emitted on the header directly, so every choice
/// is an honestly labelled window. A fixed-width Boolean decomposition pins
/// its unsigned representation, and its two low bits are constrained zero.
/// Bounding the derived final epoch excludes windows beyond the epoch domain.
///
/// The epoch indices need no absorbing into $z$, each being `epoch_start`
/// plus a circuit constant. The nullifier scalars are sponge outputs of the
/// threaded `mk`, pinned in-circuit, so the product identity alone forces
/// every member.
#[derive(Debug)]
pub struct NullifierDerive;

impl Step for NullifierDerive {
    type Aux<'source> = ();
    type Left = NoteSecret;
    type Output = NoteNullifiers;
    type Right = ();
    type Shared = ();
    /// `(epoch_start, seq)`
    type Witness<'source> = (EpochIndex, NfSeqPoly);

    const INDEX: Index = Index::new(1);

    #[expect(
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        clippy::indexing_slicing,
        clippy::missing_asserts_for_indexing,
        reason = "the fixed sponge rate divides the window width; indices are fixed"
    )]
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let epoch_start = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0)),
        )?;
        let epoch_bits = circuit::bits::<D, 32>(ctx.dr, &epoch_start)?;
        let low = &epoch_bits[0];
        let high = &epoch_bits[1];
        low.element().enforce_zero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "NullifierDerive: epoch_start is not group-aligned".into(),
            )
        })?;
        high.element().enforce_zero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "NullifierDerive: epoch_start is not group-aligned".into(),
            )
        })?;
        let width = Element::constant(
            ctx.dr,
            Fp::from(u64::try_from(NF_DERIVATION_WIDTH - 1).map_err(|_err| {
                ragu_core::Error::InvalidWitness("constant window width exceeds u64".into())
            })?),
        );
        let epoch_end = epoch_start.add(ctx.dr, &width);
        circuit::bounded::<D, 32>(ctx.dr, &epoch_end, u64::from(EPOCH_MAX)).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "NullifierDerive: window exceeds the epoch range".into(),
            )
        })?;
        let mk = left_encoded.as_gadget().mk.element.clone();
        let seq_handle =
            ctx.witness_polynomial(witness.as_ref().map(|data| data.1.as_ref().clone()))?;
        let z = ctx.derive_challenge(&seq_handle)?;
        let seq_assignment = ctx.evaluate(&seq_handle, z.value().map(|challenge| *challenge))?;
        let seq_at_z = Element::alloc(ctx.dr, &mut (), seq_assignment)?;
        let mut window_at_z = Element::constant(ctx.dr, Fp::ONE);
        let mut offset = Element::constant(ctx.dr, Fp::ONE);
        let one = Element::constant(ctx.dr, Fp::ONE);
        for _ in 0..(NF_DERIVATION_WIDTH / PoseidonFp::RATE) {
            let group_offset = offset.sub(ctx.dr, &one);
            let group_start = epoch_start.add(ctx.dr, &group_offset);
            let group = poseidon::nullifier_group_circuit(ctx.dr, &mk, &group_start)?;
            for nullifier in group {
                let index = epoch_start.add(ctx.dr, &offset);
                let factor = indexed_member_factor(ctx.dr, &nullifier, &index, &z)?;
                window_at_z = window_at_z.mul(ctx.dr, &factor)?;
                offset = offset.add(ctx.dr, &one);
            }
        }
        window_at_z
            .enforce_equal(ctx.dr, &seq_at_z)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "NullifierDerive: sequence does not match the derived window".into(),
                )
            })?;
        ctx.enforce_poly_query(&seq_handle, z, seq_at_z)?;
        let output = D::just(|| {
            let (start, seq) = witness.take();
            (
                left.take().0,
                start,
                seq.commit(),
                crate::gadgets::epoch::EpochIndexGadget::from((epoch_end).clone())
                    .value()
                    .take(),
            )
        });
        let fields = crate::stamp::headers::delegation::NoteNullifiersOutput {
            cm: (left_encoded.as_gadget().cm.element.clone()).into(),
            epoch_start: (epoch_start).into(),
            epoch_end: (epoch_end).into(),
            nf_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &seq_handle)?,
            })
            .into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
    }
}

/// Merge two adjacent derived ranges into one (`left ++ right`).
///
/// Requires the same `cm` and contiguity (`right.epoch_start ==
/// left.epoch_end + 1`). Witnesses the two range polynomials and their
/// concatenation, binds each by commit-equality, and proves the concat as the
/// product
///
/// $$
///   \mathsf{merged}(X) = \mathsf{left}(X) \cdot \mathsf{right}(X)
/// $$
///
/// since concatenation of disjoint ranges is exactly multiplication.
///
/// # Soundness
///
/// All three operands are committed and absorbed into the challenge, so the
/// product identity pins `merged`'s member multiset to the union of the
/// halves'. The contiguity check preserves the header invariant established
/// at the leaf: exactly one member per epoch in `[epoch_start, epoch_end]`,
/// so the announced range labels the member multiset truthfully.
#[derive(Debug)]
pub struct NullifierFuse;

impl Step for NullifierFuse {
    type Aux<'source> = ();
    type Left = NoteNullifiers;
    type Output = NoteNullifiers;
    type Right = NoteNullifiers;
    type Shared = ();
    /// `(left_seq, merged_seq, right_seq)`
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(12);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let left_cm = left_encoded.as_gadget().cm.element.clone();
        let right_cm = right_encoded.as_gadget().cm.element.clone();
        left_cm.enforce_equal(ctx.dr, &right_cm).map_err(|_err| {
            ragu_core::Error::InvalidWitness("NullifierFuse: note commitments differ".into())
        })?;
        let end = left_encoded.as_gadget().epoch_end.element.clone();
        let start = right_encoded.as_gadget().epoch_start.element.clone();
        let one = Element::constant(ctx.dr, Fp::ONE);
        end.add(ctx.dr, &one)
            .enforce_equal(ctx.dr, &start)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("NullifierFuse: ranges not contiguous".into())
            })?;
        let left_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|sequences| sequences.0.as_ref().clone()),
        )?;
        let merged_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|sequences| sequences.1.as_ref().clone()),
        )?;
        let right_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|sequences| sequences.2.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &left_handle,
            &left_encoded.as_gadget().nf_commit.encoding.limbs,
            "NullifierFuse: left polynomial does not match header",
        )?;
        bind_poly_handle(
            ctx,
            &right_handle,
            &right_encoded.as_gadget().nf_commit.encoding.limbs,
            "NullifierFuse: right polynomial does not match header",
        )?;
        enforce_poly_product(
            ctx,
            &left_handle,
            &right_handle,
            &merged_handle,
            "NullifierFuse: merged is not the concat of the halves",
        )?;
        let output = D::try_just(|| {
            let (_, merged_seq, _) = witness.take();
            let (output_cm, left_epoch_start, ..) = left.take();
            let (_, _, _, right_epoch_end) = right.take();
            Ok((
                (
                    output_cm,
                    left_epoch_start,
                    merged_seq.commit(),
                    right_epoch_end,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let fields = crate::stamp::headers::delegation::NoteNullifiersOutput {
            cm: (left_encoded.as_gadget().cm.element.clone()).into(),
            epoch_start: (left_encoded.as_gadget().epoch_start.element.clone()).into(),
            epoch_end: (right_encoded.as_gadget().epoch_end.element.clone()).into(),
            nf_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &merged_handle)?,
            })
            .into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            data,
            aux,
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString as _;

    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        keys::{SpendValidatingKey, private::SpendingKey},
        reddsa,
        stamp::proof::PROOF_SYSTEM,
    };

    #[test]
    fn note_seed_rejects_an_identity_authorizing_key_at_point_allocation() {
        // The validating-key wrapper's inner constructor is crate-private;
        // construct the otherwise valid identity key here to bypass builders.
        let rng = &mut StdRng::seed_from_u64(0);
        let pak = SpendingKey::random(rng).derive_proof_private();
        let supplied = (
            value::Positive::try_from(500).expect("bounded value"),
            nullifier::Trapdoor::random(rng),
            note::CommitmentTrapdoor::from(Fp::ONE),
            pak,
        );
        let (control, ()) = PROOF_SYSTEM
            .seed(rng, NoteSeed, supplied)
            .expect("finite authorizing key");
        assert!(
            PROOF_SYSTEM
                .verify(&control, &mut *rng)
                .expect("valid control")
        );
        let mut bad = supplied;
        bad.3.ak = SpendValidatingKey(
            reddsa::VerificationKey::try_from([0u8; 32]).expect("identity is canonically encoded"),
        );
        let error = PROOF_SYSTEM
            .seed(rng, NoteSeed, bad)
            .err()
            .expect("identity cannot be an affine Point witness");
        let ragu_core::Error::InvalidWitness(message) = error else {
            panic!("unexpected rejection: {error:?}");
        };
        assert_eq!(message.to_string(), "point at infinity cannot be witnessed");
    }
}
