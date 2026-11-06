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
use ragu_primitives::{Element, GadgetExt as _, Point, allocator::Allocator, io::Write};
use udon::{curve::Affine as _, field::Field as _};

use crate::{
    constants::{EPOCH_MAX, MAX_MONEY},
    digest::poseidon,
    keys::{NoteMasterKey, PaymentKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH},
    pasta::{EpAffine, Fp},
    primitives::{EpochIndex, NfSeqPoly},
    relations::{
        arithmetic as circuit, curve,
        enforce::{enforce_poly_product, indexed_member_factor},
    },
    value,
};

/// A note's certified record: its commitment, its opening, and its master key
/// (wallet-only).
///
/// `mk` is derived from the note's secrets by [`NoteSeed`] and certified here,
/// so every consuming [`NullifierDerive`] threads a genuine master key without
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
    /// `(cm, epoch_start, epoch_end)`. `epoch_end` is inclusive. Slot `O0`
    /// holds the nullifier sequence.
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let value = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(u64::from(data.0))),
        )?;
        circuit::bounded::<D, 51>(dr, &value, MAX_MONEY)?;
        let psi = Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.1)))?;
        let rcm = Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.2)))?;
        rcm.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("NoteSeed: commitment trapdoor is zero".into())
        })?;
        let nk = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.3.nk)),
        )?;
        let ak_assignment = D::try_just(|| {
            let bytes: [u8; 32] = witness.as_ref().take().3.ak.0.into();
            EpAffine::from_bytes(bytes)
                .ok_or_else(|| ragu_core::Error::InvalidWitness("invalid ak encoding".into()))
        })?;
        let ak = Point::alloc(dr, ak_assignment)?;
        let [ak_x, ak_y] = curve::coordinates(dr, &ak)?;
        let pk = poseidon::with_driver::payment_key(dr, (&ak_x, &ak_y), &nk)?;
        let mk = poseidon::with_driver::nf_master(dr, &psi, &nk)?;
        let cm = poseidon::with_driver::note_commitment(dr, &rcm, &pk, &value, &psi)?;
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
        let fields = NoteSecretOutput {
            cm,
            rcm,
            pk,
            value,
            psi,
            mk,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
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
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.1.as_ref());
        Ok(polynomials)
    }

    #[expect(
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        clippy::indexing_slicing,
        clippy::missing_asserts_for_indexing,
        reason = "the fixed sponge rate divides the window width; indices are fixed"
    )]
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let epoch_start =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.0)))?;
        epoch_start.enforce_equal(dr, &oracles.staged()[0])?;
        let epoch_bits = circuit::bits::<D, 32>(dr, &epoch_start)?;
        let low = &epoch_bits[0];
        let high = &epoch_bits[1];
        low.element().enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "NullifierDerive: epoch_start is not group-aligned".into(),
            )
        })?;
        high.element().enforce_zero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "NullifierDerive: epoch_start is not group-aligned".into(),
            )
        })?;
        // The whole window must land inside the epoch range: an index past
        // EPOCH_MAX maps to no block height, so it labels nothing. Unreachable
        // through `EpochIndex`, which cannot hold such an index; a real
        // circuit sees a raw field element and needs the check.
        let width = Element::constant(
            dr,
            Fp::from(u64::try_from(NF_DERIVATION_WIDTH - 1).map_err(|_err| {
                ragu_core::Error::InvalidWitness("constant window width exceeds u64".into())
            })?),
        );
        let epoch_end = epoch_start.add(dr, &width);
        circuit::bounded::<D, 32>(dr, &epoch_end, u64::from(EPOCH_MAX)).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "NullifierDerive: window exceeds the epoch range".into(),
            )
        })?;
        let mk = left_encoded.as_gadget().mk.clone();
        let z = oracles.zeta().clone();
        let seq_at_z = oracles.query(dr, Slot::output(0), &z)?;
        // The window's members at `z`, encoded in-circuit from the
        // sponge-derived nullifiers and their epochs.
        let mut window_at_z = Element::constant(dr, Fp::ONE);
        let mut offset = Element::constant(dr, Fp::ONE);
        let one = Element::constant(dr, Fp::ONE);
        // NF_DERIVATION_WIDTH nullifiers, PoseidonFp::RATE per sponge.
        for _ in 0..(NF_DERIVATION_WIDTH / PoseidonFp::RATE) {
            let group_offset = offset.sub(dr, &one);
            let group_start = epoch_start.add(dr, &group_offset);
            let group = poseidon::with_driver::nullifier_group(dr, &mk, &group_start)?;
            for nullifier in group {
                let index = epoch_start.add(dr, &offset);
                let factor = indexed_member_factor(dr, &nullifier, &index, &z)?;
                window_at_z = window_at_z.mul(dr, &factor)?;
                offset = offset.add(dr, &one);
            }
        }
        window_at_z.enforce_equal(dr, &seq_at_z).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "NullifierDerive: sequence does not match the derived window".into(),
            )
        })?;
        let output = D::just(|| {
            let (start, _) = witness.take();
            (
                left.take().0,
                start,
                circuit::epoch_value(&epoch_end).take(),
            )
        });
        let fields = NoteNullifiersOutput {
            cm: left_encoded.as_gadget().cm.clone(),
            epoch_start,
            epoch_end,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
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
    /// `merged_seq`
    type Witness<'source> = NfSeqPoly;

    const INDEX: Index = Index::new(12);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.as_ref());
        Ok(polynomials)
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
        let left_cm_element = left_encoded.as_gadget().cm.clone();
        let right_cm = right_encoded.as_gadget().cm.clone();
        left_cm_element
            .enforce_equal(dr, &right_cm)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("NullifierFuse: note commitments differ".into())
            })?;
        let end = left_encoded.as_gadget().epoch_end.clone();
        let start = right_encoded.as_gadget().epoch_start.clone();
        let one = Element::constant(dr, Fp::ONE);
        end.add(dr, &one)
            .enforce_equal(dr, &start)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("NullifierFuse: ranges not contiguous".into())
            })?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::right(0),
            &Slot::output(0),
            "NullifierFuse: merged is not the concat of the halves",
        )?;
        let output = D::try_just(|| {
            let (left_cm, left_epoch_start, _) = left.take();
            let (_, _, right_epoch_end) = right.take();
            Ok(((left_cm, left_epoch_start, right_epoch_end), ()))
        })?;
        let (data, aux) = output.cast();
        let fields = NoteNullifiersOutput {
            cm: left_encoded.as_gadget().cm.clone(),
            epoch_start: left_encoded.as_gadget().epoch_start.clone(),
            epoch_end: right_encoded.as_gadget().epoch_end.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}
