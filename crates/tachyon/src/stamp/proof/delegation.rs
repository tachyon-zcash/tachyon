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

/// A note's commitment, opening and master key (wallet-only).
///
/// [`NullifierDerive`] reads `cm` and `mk`, while
/// [`SpendBind`](super::spend::SpendBind) reads `cm`, `mk`, the value and
/// `pk`.
///
/// # Injectivity
///
/// [`NoteSeed`] outputs this header. Every verified `NoteSecret` asserts that
/// its prover knows a point $\mathsf{ak}$ and an element $\mathsf{nk}$ where
///
/// - `note.pk` is the [payment key](poseidon::payment_key) of $\mathsf{ak}$ and
///   $\mathsf{nk}$,
/// - `mk` is the [master key](poseidon::nf_master) of `note.psi` and
///   $\mathsf{nk}$,
/// - `cm` is the [note commitment](poseidon::note_commitment) of `note`,
/// - `note.value` is an integer in `0..=MAX_MONEY`,
/// - `note.rcm` is nonzero.
///
/// `cm` determines all four note fields; `pk` fixes both keys, so $\psi$ and
/// $\mathsf{nk}$ fix `mk` and every epoch's nullifier. The converse fails:
/// changing $\mathsf{ak}$, value or `rcm` alone leaves `mk` and all nullifiers
/// unchanged. Steps joining headers for one note therefore match `cm`.
///
/// # Zero commitment trapdoor
///
/// Since `cm` fixes `rcm` and [`NoteSeed`] excludes zero, a zero-`rcm` note has
/// no `NoteSecret` for [`SpendBind`](super::spend::SpendBind).
/// [`OutputBind`](super::output::OutputBind),
/// [`FeeFuse`](super::stamp::FeeFuse) and [`FeeSeed`](super::stamp::FeeSeed)
/// enforce the same check for outputs and fee change. Recipients check
/// unverified openings before calling [`Note::commitment`], which panics on
/// zero `rcm`.
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

/// A note's nullifiers over `epoch_start..=epoch_end` (wallet-only).
///
/// # Injectivity
///
/// [`NullifierDerive`] and [`NullifierFuse`] output this header. Every verified
/// `NoteNullifiers` asserts `epoch_start <= epoch_end <= EPOCH_MAX` over the
/// integers, a prover-known verified [`NoteSecret`] carrying `cm` and master
/// key $\mathsf{mk}$, and an [`NfSeqPoly`] equal to
///
/// $$
///   S(X) = \prod_{e} F_{e,\ \mathsf{nf}_e}(X)
/// $$
///
/// across $e \in \text{epoch\_start}..=\text{epoch\_end}$, where $F_{i,m}$ is
/// the [indexed multiset](crate::collections::indexed_multiset) encoding of
/// $(i, m)$ and $\mathsf{nf}_e$ is the
/// [nullifier](poseidon::nullifier_group) of $\mathsf{mk}$ at $e$.
///
/// `cm` stands for the note and determines $\mathsf{mk}$ ([`NoteSecret`]), so
/// the three header fields fix $S$. Both epoch fields use
/// [`EpochIndex`](gadgets::epoch::EpochIndex) gadgets, making epoch equations
/// hold over the integers. Because every epoch lies within the encoding's index
/// bound, $S$ consists of one distinct irreducible factor per epoch in the
/// range, determining the set of $(e, \mathsf{nf}_e)$ tuples and restricting
/// any divisor of $S$ to a scalar multiple of a subset of those factors.
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
/// Seed step. Witnesses the note's value, trapdoors and proof authorizing key.
/// `nk` stays inside the step while the header exports its digests `pk` and
/// `mk`.
///
/// # Soundness
///
/// Reading no input or challenge, the circuit enforces every [`NoteSecret`]
/// equation directly on its wires. It range-checks `value` to `0..=MAX_MONEY`,
/// holds `rcm` nonzero, and allocates $\mathsf{ak}$ as a non-identity curve
/// point. It derives `pk` from $\mathsf{ak}$ and $\mathsf{nk}$, `mk` from
/// $\psi$ and the same $\mathsf{nk}$ wire, and `cm` from `rcm`, `pk`, `value`
/// and the same $\psi$ wire.
///
/// This step does not show that `cm` was published.
/// [`SpendableInit`](super::spendable::SpendableInit)
/// or [`QrSpendableInit`](super::spendable::QrSpendableInit) places `cm` among
/// the roots of a stamp absorption or bucket, establishing publication once
/// the absorption's anchor or the bucket's `anchor_next`, respectively, is
/// canonical.
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
/// # Soundness
///
/// The input fixes `mk` and `cm`; staging fixes `epoch_start` before $\zeta$.
/// Its epoch-width packing has two zero low bits, aligning it to four.
/// Range-checking `epoch_end = epoch_start + 15` bounds all sixteen epochs by
/// `EPOCH_MAX` without wrapping.
///
/// Four `Tachyon-NfDerive` sponges absorb `mk` and `epoch_start + 4k` to
/// squeeze `PoseidonFp::RATE` nullifiers across each four-epoch group. Pairing
/// each nullifier with its epoch, the circuit multiplies all sixteen factors at
/// $\zeta$ and equates the product with the pre-committed output sequence's
/// opening, establishing the product [`NoteNullifiers`] asserts while copying
/// `cm` from the input.
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
/// # Soundness
///
/// Matching `cm` fixes one master key; `left.epoch_end + 1 ==
/// right.epoch_start` over the integers joins adjacent ranges. All three
/// sequences precede $\zeta$. Checking output = left × right with one opening
/// each preserves one factor per epoch across
/// `left.epoch_start..=right.epoch_end`.
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
