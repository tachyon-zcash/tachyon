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
    PoseidonPermutation as _,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, OnlinePoly, Padding, Suffix},
    maybe::Maybe as _,
    pasta::{Pasta, PoseidonFp},
    primitives::{Element, GadgetExt as _, Point, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
};
use udon::{curve::Affine as _, field::Field as _};

use crate::{
    digest::poseidon,
    gadgets,
    keys::{NoteMasterKey, PaymentKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH},
    pasta::{EpAffine, Fp},
    primitives::{EpochIndex, NfSeqPoly},
    value,
};

/// The polynomial whose roots are a sequence of nullifiers, each indexed by
/// its epoch.
#[derive(Clone, Copy, Debug)]
pub struct NfSeq;

impl OnlinePoly for NfSeq {}

/// A note's certified record: its commitment, its opening, and its master key
/// (wallet-only).
///
/// [`NoteSeed`] proves that `mk` belongs to the note, so [`NullifierDerive`]
/// can use it without proving the note's opening again.
/// [`SpendBind`](super::spend::SpendBind) reads it.
#[derive(Clone, Debug)]
pub struct NoteSecret;

#[derive(Gadget, Write)]
pub struct NoteSecretOutput<'dr, D: Driver<'dr>> {
    pub cm: Element<'dr, D>,
    #[ragu(gadget)]
    pub note: gadgets::note::Note<'dr, D>,
    #[ragu(gadget)]
    pub mk: gadgets::master::NoteMasterKey<'dr, D>,
}

impl Header<Fp> for NoteSecret {
    /// `(cm, note, mk)`
    type Data = (note::Commitment, Note, NoteMasterKey);
    type OnlinePolyCommit = (Padding, Padding);
    type Output = Kind![Fp; NoteSecretOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteSecretOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(cm, ..)| Fp::from(cm)),
            )?,
            note: gadgets::note::Note::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(_, note, _)| note),
            )?,
            mk: gadgets::master::NoteMasterKey {
                element: Element::alloc(
                    dr,
                    allocator,
                    witness.as_ref().map(|&(_, _, NoteMasterKey(mk))| mk),
                )?,
            },
        })
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// Covers epochs `[epoch_start, epoch_end]`. The output polynomial is an
/// [`NfSeqPoly`] with exactly one member per covered epoch. That
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

#[derive(Gadget, Write)]
pub struct NoteNullifiersOutput<'dr, D: Driver<'dr>> {
    pub cm: Element<'dr, D>,
    #[ragu(gadget)]
    pub epoch_start: gadgets::epoch::EpochIndex<'dr, D>,
    #[ragu(gadget)]
    pub epoch_end: gadgets::epoch::EpochIndex<'dr, D>,
}

impl Header<Fp> for NoteNullifiers {
    /// `(cm, epoch_start, epoch_end)`
    type Data = (note::Commitment, EpochIndex, EpochIndex);
    type OnlinePolyCommit = (NfSeq, Padding);
    type Output = Kind![Fp; NoteNullifiersOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteNullifiersOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(cm, ..)| Fp::from(cm)),
            )?,
            epoch_start: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(_, epoch_start, _)| epoch_start),
            )?,
            epoch_end: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(.., epoch_end)| epoch_end),
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
        _oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let value = gadgets::value::Positive::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(value, ..)| value),
        )?;
        let psi = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(_, psi, ..)| Fp::from(psi)),
        )?;
        let rcm = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(_, _, rcm, _)| Fp::from(rcm)),
        )?;
        rcm.clone().enforce_nonzero(dr)?;
        let nk = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(.., pak)| Fp::from(pak.nk)),
        )?;
        #[expect(
            clippy::expect_used,
            reason = "ak is a typed RedPallas verification key"
        )]
        let ak_assignment = D::just(|| {
            let &(.., pak) = witness.as_ref().take();
            let bytes: [u8; 32] = pak.ak.0.into();
            EpAffine::from_bytes(bytes).expect("a verification key encodes a curve point")
        });
        let ak = Point::alloc(dr, ak_assignment)?;
        let pk = poseidon::circuit::payment_key(dr, &ak, &nk)?;
        let mk = poseidon::circuit::nf_master(dr, &psi, &nk)?;
        let circuit_note = gadgets::note::Note {
            rcm,
            pk,
            value,
            psi,
        };
        let cm = circuit_note.commitment(dr)?;
        let output = D::just(|| {
            let (note_value, note_psi, note_rcm, _) = witness.take();
            let note = Note {
                pk: PaymentKey::from(*circuit_note.pk.value().take()),
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
            note: circuit_note,
            mk: gadgets::master::NoteMasterKey { element: mk },
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
/// The window starts on a group boundary. One `Tachyon-NfDerive` sponge per
/// group absorbs the note's master key and the group's first epoch, then
/// produces `PoseidonFp::RATE` nullifiers.
///
/// # Soundness
///
/// The input proof identifies the note's master key. The start epoch is fixed
/// before the challenge; it must be a multiple of the sponge rate, and the
/// final epoch must remain in range. The circuit derives every nullifier and
/// index from those inputs. Opening the committed sequence at the random
/// challenge checks the whole window, whose bounds are published on the output
/// header.
///
/// # Panics
///
/// Proving panics if the window runs past `EPOCH_MAX` (`epoch_start` above
/// `EPOCH_MAX - 15`).
///
/// Opens the derived sequence once.
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

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(NfSeq, witness.1.as_ref().iter_coeffs().collect::<Vec<_>>())
            .stage([Fp::from(witness.0)]))
    }

    #[expect(
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        clippy::indexing_slicing,
        reason = "the fixed sponge rate divides the window width; indices are fixed"
    )]
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let secret = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let output = D::just(|| {
            let (epoch_start, _) = witness.take();
            #[expect(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                reason = "the window width is a small constant"
            )]
            let epoch_end = EpochIndex::new(
                u32::from(epoch_start) + const { (NF_DERIVATION_WIDTH - 1) as u32 },
            );
            let (cm, ..) = left.take();
            (cm, epoch_start, epoch_end)
        });
        let epoch_start = gadgets::uint::Uint::alloc(
            dr,
            output
                .as_ref()
                .map(|&(_, epoch_start, _)| Fp::from(epoch_start)),
        )
        .and_then(|bits| gadgets::epoch::EpochIndex::from_group_start(dr, &bits))?;
        oracles.staged()[0].enforce_equal(dr, &epoch_start)?;
        // The whole window must land inside the epoch range: an index past
        // EPOCH_MAX maps to no block height, so it labels nothing.
        #[expect(clippy::as_conversions, reason = "constant value")]
        let width = Element::constant(dr, Fp::from(const { (NF_DERIVATION_WIDTH - 1) as u64 }));
        let epoch_end = epoch_start.add(dr, &width);
        let z = oracles.zeta().clone();
        let seq_at_z = oracles.output(NfSeq).open(dr, &z)?;
        // The window's members at `z`, encoded in-circuit from the
        // sponge-derived nullifiers and their epochs.
        let mut window_at_z = Element::constant(dr, Fp::ONE);
        let mut index = (*epoch_start).clone();
        let one = Element::constant(dr, Fp::ONE);
        // NF_DERIVATION_WIDTH nullifiers, PoseidonFp::RATE per sponge, each
        // sponge keyed on its group's first epoch.
        for _ in 0..(NF_DERIVATION_WIDTH / PoseidonFp::RATE) {
            for nullifier in poseidon::circuit::nullifier_group(dr, &secret.mk.element, &index)? {
                let factor = gadgets::indexed_multiset::Member {
                    index: index.clone(),
                    value: nullifier,
                }
                .eval(dr, &z)?;
                window_at_z = window_at_z.mul(dr, &factor)?;
                index = index.add(dr, &one);
            }
        }
        window_at_z.enforce_equal(dr, &seq_at_z)?;
        let fields = NoteNullifiersOutput {
            cm: secret.cm.clone(),
            epoch_start,
            epoch_end: gadgets::uint::Uint::from_element(dr, &epoch_end)
                .and_then(|bits| gadgets::epoch::EpochIndex::from_bits(dr, &bits))?,
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
/// left.epoch_end + 1`). Proves the concatenation of the input ranges as the
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
///
/// Opens both input sequences and their concatenation once each.
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

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new().poly(NfSeq, witness.0.as_ref().iter_coeffs().collect::<Vec<_>>()))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let left_nullifiers = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let right_nullifiers = right_encoded.as_gadget();
        left_nullifiers.cm.enforce_equal(dr, &right_nullifiers.cm)?;
        let one = Element::constant(dr, Fp::ONE);
        left_nullifiers
            .epoch_end
            .add(dr, &one)
            .enforce_equal(dr, &right_nullifiers.epoch_start)?;
        let z = oracles.zeta().clone();
        let left_seq = oracles.left(NfSeq).open(dr, &z)?;
        let right_seq = oracles.right(NfSeq).open(dr, &z)?;
        let merged_seq = oracles.output(NfSeq).open(dr, &z)?;
        let expected_seq = left_seq.mul(dr, &right_seq)?;
        merged_seq.enforce_equal(dr, &expected_seq)?;
        let data = D::just(|| {
            let (left_cm, left_epoch_start, _) = left.take();
            let (_, _, right_epoch_end) = right.take();
            (left_cm, left_epoch_start, right_epoch_end)
        });
        let fields = NoteNullifiersOutput {
            cm: left_nullifiers.cm.clone(),
            epoch_start: left_nullifiers.epoch_start.clone(),
            epoch_end: right_nullifiers.epoch_end.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

#[cfg(test)]
mod tests;
