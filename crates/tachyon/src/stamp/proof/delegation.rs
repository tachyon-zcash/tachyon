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
    Encoded, Header, Index, PoseidonPermutation as _, Step, StepCtx,
    pasta::{Eq, Fp, PoseidonFp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_primitives::{Element, GadgetExt as _};
use udon::{curve::Projective as _, field::Field as _};

pub use crate::stamp::headers::delegation::{NoteNullifiers, NoteSecret};
use crate::{
    collections::indexed_multiset,
    constants::EPOCH_MAX,
    keys::ProofAuthorizingKey,
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH},
    primitives::{EpochIndex, NfSeqPoly},
    ragu_constraint::{enforce_equal_point, enforce_zero},
    relations::enforce::{bind_poly_handle, enforce_poly_product},
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
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (value, psi, rcm, pak) = witness.take();
            let note = Note {
                pk: pak.derive_payment_key(),
                value,
                psi,
                rcm,
            };
            let mk = pak.nk.derive_note_private(note.psi);
            let cm = note.commitment();
            Ok(((cm, note, mk), ()))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
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
/// members by a single opening at a free $z$ against their natively encoded
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
/// is an honestly labelled window. (The alignment constraint
/// is a native remainder fed to `enforce_zero` under mock ragu; a real
/// circuit needs a low-bit decomposition of the witnessed epoch, since
/// $4q = e$ is always solvable in the field.)
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
        #[expect(
            clippy::as_conversions,
            clippy::integer_division_remainder_used,
            reason = "the group width is a small constant"
        )]
        let native = D::try_just(|| {
            let (epoch_start, seq) = witness.take();
            let (cm, _note, mk) = left.take();
            let () = right.take();
            enforce_zero(
                Fp::from(u64::from(epoch_start) % (PoseidonFp::RATE as u64)),
                "NullifierDerive: epoch_start is not group-aligned",
            )?;

            // The whole window must land inside the epoch range: an index past
            // EPOCH_MAX maps to no block height, so it labels nothing. Unreachable
            // through `EpochIndex`, which cannot hold such an index; a real
            // circuit sees a raw field element and needs the check.
            #[expect(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                reason = "the window width is a small constant"
            )]
            let epoch_end = u32::from(epoch_start)
                .checked_add(NF_DERIVATION_WIDTH as u32 - 1)
                .filter(|last| *last <= EPOCH_MAX)
                .map(EpochIndex::new)
                .ok_or_else(|| {
                    ragu_core::Error::InvalidWitness(
                        "NullifierDerive: window exceeds the epoch range".into(),
                    )
                })?;

            let nullifiers = mk.derive_window(epoch_start);
            let output = (cm, epoch_start, seq.commit(), epoch_end);
            Ok((seq, output, nullifiers))
        })?;
        let seq_handle =
            ctx.witness_polynomial(native.as_ref().map(|result| result.0.as_ref().clone()))?;
        let z = ctx.derive_challenge(&seq_handle)?;
        let seq_assignment = ctx.evaluate(&seq_handle, z.value().map(|challenge| *challenge))?;
        let seq_at_z = Element::alloc(ctx.dr, &mut (), seq_assignment)?;
        let output = native.as_ref().map(|result| result.1);
        let z_value = z.value().map(|challenge| *challenge);
        let window_at_z = D::try_just(|| {
            let challenge = z_value.take();
            let (_, output_data, nullifiers) = native.take();
            Ok(indexed_multiset::direct_eval(
                (output_data.1.into()..).zip(nullifiers.map(Fp::from)),
                challenge,
            ))
        })?;
        let window_assignment = Element::alloc(ctx.dr, &mut (), window_at_z)?;
        seq_at_z
            .enforce_equal(ctx.dr, &window_assignment)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "NullifierDerive: sequence does not match the derived window".into(),
                )
            })?;
        ctx.enforce_poly_query(&seq_handle, z, seq_at_z)?;
        let encoded =
            Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), output.clone())?;
        Ok((
            (left_encoded, right_encoded, encoded),
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
        let _precheck = D::try_just(|| {
            let (left_seq, _, right_seq) = witness.clone().take();
            let (left_cm, _, left_nf_commit, left_epoch_end) = left.clone().take();
            let (right_cm, right_epoch_start, right_nf_commit, _) = right.clone().take();
            enforce_zero(
                Fp::from(left_cm) - Fp::from(right_cm),
                "NullifierFuse: note commitments differ",
            )?;
            enforce_zero(
                Fp::from(right_epoch_start) - Fp::from(left_epoch_end) - Fp::ONE,
                "NullifierFuse: ranges not contiguous",
            )?;
            enforce_equal_point(
                Eq::from(left_seq.commit()),
                Eq::from(left_nf_commit),
                "NullifierFuse: left polynomial does not match header",
            )?;
            enforce_equal_point(
                Eq::from(right_seq.commit()),
                Eq::from(right_nf_commit),
                "NullifierFuse: right polynomial does not match header",
            )?;
            Ok(())
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
            left.as_ref().map(|data| Eq::from(data.2).to_affine()),
            "NullifierFuse: left polynomial does not match header",
        )?;
        bind_poly_handle(
            ctx,
            &right_handle,
            right.as_ref().map(|data| Eq::from(data.2).to_affine()),
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
            let (left_cm, left_epoch_start, ..) = left.take();
            let (_, _, _, right_epoch_end) = right.take();
            Ok((
                (
                    left_cm,
                    left_epoch_start,
                    merged_seq.commit(),
                    right_epoch_end,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}
