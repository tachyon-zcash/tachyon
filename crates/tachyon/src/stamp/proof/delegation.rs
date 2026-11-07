//! Prove a fusable range of a note's per-epoch nullifiers.
//!
//! Three steps. [`NoteSeed`] certifies the note's commitment and master
//! key; [`NullifierDerive`] consumes that seed and exports one whole window;
//! and [`NullifierFuse`] concatenates adjacent windows.
//!
//! All headers are wallet-only, and no key material rides the exported
//! [`NoteNullifiers`].

extern crate alloc;

use alloc::vec::Vec;

use ragu::{
    header::{Header, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
};
use ragu_core::{
    PoseidonPermutation as _,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::{Pasta, PoseidonFp},
};
use ragu_primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write};
use udon::field::Field as _;

use crate::{
    collections::indexed_multiset,
    constants::EPOCH_MAX,
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH},
    pasta::Fp,
    primitives::{EpochIndex, NfSeqPoly},
    ragu_constraint::enforce_zero,
    relations::enforce::enforce_poly_product,
    value,
};

/// A note's certified record: its commitment, its opening, and its master key
/// (wallet-only).
///
/// `mk` is derived natively from the note's secrets and certified here, so
/// every consuming [`NullifierDerive`] threads a genuine master key without
/// re-witnessing the note. `note` is the opening `cm` commits to.
/// [`SpendBind`](super::spend::SpendBind) reads it.
#[derive(Clone, Debug)]
pub struct NoteSecret;

/// `NoteSecret` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct NoteSecretOutput<'dr, D: Driver<'dr>> {
    /// `cm`.
    pub cm: Element<'dr, D>,
    /// `note.rcm`.
    pub rcm: Element<'dr, D>,
    /// `note.pk`.
    pub pk: Element<'dr, D>,
    /// `note.value`.
    pub value: Element<'dr, D>,
    /// `note.psi`.
    pub psi: Element<'dr, D>,
    /// `mk`.
    pub mk: Element<'dr, D>,
}

impl Header<Fp> for NoteSecret {
    /// `(cm, note, mk)`
    type Data = (note::Commitment, Note, NoteMasterKey);
    type Output = Kind![Fp; NoteSecretOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteSecretOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            rcm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1.rcm)),
            )?,
            pk: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1.pk)),
            )?,
            value: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(u64::from(fields.1.value))),
            )?,
            psi: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1.psi)),
            )?,
            mk: Element::alloc(dr, allocator, witness.as_ref().map(|fields| fields.2.0))?,
        })
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(cm, epoch_start, nf_commit, epoch_end)`: covers epochs
/// `[epoch_start, epoch_end]`; `nf_commit` commits the range's nullifier
/// sequence as an [`NfSeqPoly`], exactly one member per covered epoch. That
/// invariant is established at [`NullifierDerive`], preserved by
/// [`NullifierFuse`]'s contiguity check, and what the divisibility binds
/// lean on for per-epoch completeness. `cm` binds the range to the real
/// note.
///
/// No consumer reads the range. It serves [`NullifierFuse`]'s contiguity
/// check, which keeps the product squarefree, and squarefreeness forces a
/// tested sequence's members distinct at
/// [`UnspentBind`](super::pool::UnspentBind).
///
/// Masking is the consuming step's responsibility.
#[derive(Clone, Debug)]
pub struct NoteNullifiers;

/// `NoteNullifiers` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct NoteNullifiersOutput<'dr, D: Driver<'dr>> {
    /// `cm`.
    pub cm: Element<'dr, D>,
    /// `epoch_start`.
    pub epoch_start: Element<'dr, D>,
    /// `epoch_end`.
    pub epoch_end: Element<'dr, D>,
}

impl Header<Fp> for NoteNullifiers {
    /// `(cm, epoch_start, epoch_end)`
    type Data = (note::Commitment, EpochIndex, EpochIndex);
    type Output = Kind![Fp; NoteNullifiersOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteNullifiersOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            epoch_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            epoch_end: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?,
        })
    }
}

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

impl Step<Pasta> for NoteSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NoteSecret;
    type Right = ();
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
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
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
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
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
/// `epoch_start` is staged before $z$; each epoch index is that start plus a
/// circuit constant. The nullifier scalars are sponge outputs of the
/// threaded `mk`, pinned in-circuit, so the product identity alone forces
/// every member.
///
/// Polynomial inventory: `O0` is the derived sequence; stage `epoch_start`.
#[derive(Debug)]
pub struct NullifierDerive;

impl Step<Pasta> for NullifierDerive {
    type Aux<'source> = ();
    type Left = NoteSecret;
    type Output = NoteNullifiers;
    type Right = ();
    /// `(epoch_start, seq)`
    type Witness<'source> = (EpochIndex, NfSeqPoly);

    const INDEX: Index = Index::new(1);
    const NUM_STAGED: usize = 1;

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        Ok(alloc::vec![Fp::from(witness.0)])
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.1.as_ref().iter_coeffs().collect(),
            alloc::vec![Fp::ONE],
        ])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
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

            // NF_DERIVATION_WIDTH nullifiers, PoseidonFp::RATE per sponge.
            let nullifiers = mk.derive_window(epoch_start);
            let output = (cm, epoch_start, epoch_end);
            Ok((seq, output, nullifiers))
        })?;
        let epoch_start = Element::alloc(
            dr,
            &mut (),
            native.as_ref().map(|result| Fp::from(result.1.1)),
        )?;
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        epoch_start.enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let seq_at_z = oracles.query(dr, Slot::output(0), &z)?;
        let output = native.as_ref().map(|result| result.1);
        let z_value = z.value().map(|challenge| *challenge);
        // The window's members at `z`, encoded natively from the
        // sponge-derived nullifiers and their epochs.
        let window_at_z = D::try_just(|| {
            let challenge = z_value.take();
            let (_, output_data, nullifiers) = native.take();
            Ok(indexed_multiset::direct_eval(
                (output_data.1.into()..).zip(nullifiers.map(Fp::from)),
                challenge,
            ))
        })?;
        let window_assignment = Element::alloc(dr, &mut (), window_at_z)?;
        seq_at_z
            .enforce_equal(dr, &window_assignment)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "NullifierDerive: sequence does not match the derived window".into(),
                )
            })?;
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), output.clone())?;
        Ok(((left_encoded, right_encoded, encoded), output, D::unit()))
    }
}

/// Merge two adjacent derived ranges into one (`left ++ right`).
///
/// Requires the same `cm` and contiguity (`right.epoch_start ==
/// left.epoch_end + 1`). Witnesses the two range polynomials and their
/// concatenation, and proves the concat over the child slots as the product
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
///
/// Polynomial inventory: `L0` and `R0` are the halves, `O0` their
/// concatenation.
#[derive(Debug)]
pub struct NullifierFuse;

impl Step<Pasta> for NullifierFuse {
    type Aux<'source> = ();
    type Left = NoteNullifiers;
    type Output = NoteNullifiers;
    type Right = NoteNullifiers;
    /// `(merged_seq,)`
    type Witness<'source> = (NfSeqPoly,);

    const INDEX: Index = Index::new(12);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.0.as_ref().iter_coeffs().collect(),
            alloc::vec![Fp::ONE],
        ])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (left_cm, left_epoch_start, left_epoch_end) = left.take();
            let (right_cm, right_epoch_start, right_epoch_end) = right.take();
            enforce_zero(
                Fp::from(left_cm) - Fp::from(right_cm),
                "NullifierFuse: note commitments differ",
            )?;
            enforce_zero(
                Fp::from(right_epoch_start) - Fp::from(left_epoch_end) - Fp::ONE,
                "NullifierFuse: ranges not contiguous",
            )?;
            Ok(((left_cm, left_epoch_start, right_epoch_end), ()))
        })?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::right(0),
            &Slot::output(0),
            "NullifierFuse: merged is not the concat of the halves",
        )?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}
