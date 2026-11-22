//! Prove a fusable range of a note's per-epoch nullifiers.
//!
//! Three steps. [`NoteSeed`] certifies the note's commitment and master
//! key; [`NullifierDerive`] consumes that seed and exports one whole window;
//! and [`NullifierFuse`] concatenates adjacent windows.
//!
//! All headers are wallet-only, and no key material rides the exported
//! [`NoteNullifiers`].

use ragu::{
    PoseidonPermutation as _,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Padding, Suffix},
    maybe::Maybe as _,
    pasta::{Pasta, PoseidonFp},
    primitives::{Element, GadgetExt as _, Point, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::{curve::Affine as _, field::Field as _},
};

use crate::{
    digest::poseidon,
    gadgets,
    keys::{NoteMasterKey, PaymentKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::{self, NF_DERIVATION_WIDTH},
    pasta::{EpAffine, Fp},
    primitives::{EpochIndex, NfSeqPoly, PolySlot},
    value,
};

/// A note's commitment, its opening and its master key (wallet-only).
///
/// [`NullifierDerive`] reads `cm` and `mk`.
/// [`SpendBind`](super::spend::SpendBind) reads `cm`, `mk`, the value and
/// `pk`.
///
/// # Injectivity
///
/// [`NoteSeed`] outputs this header. A verified `NoteSecret` asserts that
/// its prover knows a point $\mathsf{ak}$ and an element $\mathsf{nk}$ for
/// which
///
/// - `note.pk` is the [payment key](poseidon::payment_key) of $\mathsf{ak}$ and
///   $\mathsf{nk}$,
/// - `mk` is the [master key](poseidon::nf_master) of `note.psi` and
///   $\mathsf{nk}$,
/// - `cm` is the [note commitment](poseidon::note_commitment) of `note`,
/// - `note.value` is an integer in `0..=MAX_MONEY`,
/// - `note.rcm` is nonzero, which no step relies on.
///
/// `cm` stands for the note. It determines the four fields of `note`, the
/// note's `pk` determines $\mathsf{ak}$ and $\mathsf{nk}$, and $\psi$ and
/// $\mathsf{nk}$ determine `mk`. Every verified `NoteSecret` of one `cm`
/// therefore has the same `mk`, which stands for the note's nullifiers at
/// every epoch.
///
/// `mk` does not determine `cm`. Two notes with one $\psi$ and one
/// $\mathsf{nk}$ have one `mk` and the same nullifiers, whatever their
/// $\mathsf{ak}$, values and `rcm`. Steps that join two headers of a note
/// compare `cm`.
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

/// A note's nullifiers over the epochs `epoch_start..=epoch_end`
/// (wallet-only).
///
/// # Injectivity
///
/// [`NullifierDerive`] and [`NullifierFuse`] output this header. A verified
/// `NoteNullifiers` asserts that `epoch_start <= epoch_end` as integers, that
/// its prover knows a verified [`NoteSecret`] with this `cm` and a master key
/// $\mathsf{mk}$, and that its [`NfSeqPoly`] is
///
/// $$
///   S(X) = \prod_{e} F_{e,\ \mathsf{nf}_e}(X)
/// $$
///
/// over the epochs $e$ of `epoch_start..=epoch_end`. $F_{i,m}$ is the
/// [indexed multiset](crate::collections::indexed_multiset)'s encoding of
/// member $m$ at index $i$, and $\mathsf{nf}_e$ is the
/// [nullifier](poseidon::nullifier_group) of $\mathsf{mk}$ at epoch $e$.
///
/// `cm` stands for the note whose nullifiers these are. It determines
/// $\mathsf{mk}$ ([`NoteSecret`]), so the three fields determine $S$. Both
/// epochs are [`EpochIndex`](gadgets::epoch::EpochIndex) gadgets, so an
/// equation between two epochs holds over the integers. Epochs are within the
/// encoding's index bound, so $S$ has one irreducible factor for each epoch of
/// the range, all different, and no other factor. $S$ therefore determines the
/// tuples $(e, \mathsf{nf}_e)$, and a polynomial that divides $S$ is a scalar
/// times the factors of some of those epochs.
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
    type OnlinePolyCommit = (PolySlot<NfSeqPoly>, Padding);
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
/// authorizing key. `nk` stays inside the step. The header carries `pk` and
/// `mk`, which are digests of it.
///
/// # Soundness
///
/// The step reads no input and no challenge, and builds its output header from
/// its own wires. `value` is allocated with a range check to `0..=MAX_MONEY`
/// and `rcm` is held nonzero. $\mathsf{ak}$ is allocated as a point, which
/// enforces the curve equation and has no assignment for the identity. One
/// $\mathsf{nk}$ wire feeds the `pk` and `mk` digests, one $\psi$ wire feeds
/// `mk` and `cm`, and the `pk` wire feeds `cm`. These are the equations
/// [`NoteSecret`] asserts.
///
/// The step does not show that `cm` was ever published.
/// [`SpendableInit`](super::spendable::SpendableInit) and
/// [`QrSpendableInit`](super::spendable::QrSpendableInit) show that.
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
/// `mk` and `cm` come from the input header and `epoch_start` is staged, so
/// all three are fixed before the challenge. The circuit packs `epoch_start`
/// from the bits of the epoch width with the two lowest held to zero, so it is
/// a multiple of four. `epoch_end` is `epoch_start + 15` and is range-checked,
/// so the sum does not wrap.
///
/// Each of the four sponges absorbs `mk` and `epoch_start + 4k`, and its four
/// squeezes are the nullifiers of `mk` at that group's epochs. The circuit
/// pairs each nullifier with its epoch, multiplies the sixteen factors at
/// $\zeta$ and equates the product with the output sequence's opening there.
/// The factors and the sequence are fixed before $\zeta$, so the sequence is
/// the product [`NoteNullifiers`] asserts.
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
        let seq = &witness.1;
        Ok(NfSeqPoly::SLOT
            .poly(Prepared::new(), seq)
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
        let seq_at_z = oracles.output(NfSeqPoly::SLOT).open(dr, &z)?;
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
            epoch_end: gadgets::epoch::EpochIndex::from_element(dr, epoch_end)?,
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
/// The inputs' `cm` are held equal, so both sequences hold nullifiers of one
/// master key. `left.epoch_end + 1` is held equal to `right.epoch_start`, an
/// equation over the integers, so the right range starts on the epoch after
/// the left range ends. All three sequences are committed before the
/// challenge, and the output's opening at $\zeta$ is held to the product of
/// the inputs' openings. The output sequence therefore has one factor for each
/// epoch of `left.epoch_start..=right.epoch_end`.
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
        let merged_seq = &witness.0;
        Ok(NfSeqPoly::SLOT.poly(Prepared::new(), merged_seq))
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
        let left_seq = oracles.left(NfSeqPoly::SLOT).open(dr, &z)?;
        let right_seq = oracles.right(NfSeqPoly::SLOT).open(dr, &z)?;
        let merged_seq = oracles.output(NfSeqPoly::SLOT).open(dr, &z)?;
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
