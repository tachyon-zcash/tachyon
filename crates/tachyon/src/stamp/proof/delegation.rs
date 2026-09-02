//! Prove a fusable range of a note's per-epoch nullifiers.
//!
//! Three steps. [`NfMasterSeed`] certifies the note's commitment and master
//! key; [`NfDerive`] consumes that seed and exports one whole window; and
//! [`NullifierFuse`] concatenates adjacent windows.
//!
//! All headers are wallet-only, and no key material rides the exported
//! [`NullifierDerivation`].

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};
use ragu_arithmetic::PoseidonPermutation as _;
use ragu_pasta::PoseidonFp;

use crate::{
    collections::indexed_multiset,
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    primitives::{EpochIndex, NfSeqCommit, NfSeqPoly},
    relations::{
        constraint::{enforce_equal_point, enforce_zero},
        enforce::enforce_poly_product,
    },
};

/// A note's certified commitment and master key (wallet-only).
///
/// `mk` is derived natively from the note's secrets and certified here, so
/// every consuming [`NfDerive`] threads a genuine master key without
/// re-witnessing the note. `cm` rides along for the derivation's consumers to
/// bind against.
#[derive(Clone, Debug)]
pub struct NfMasterHeader;

impl Header for NfMasterHeader {
    /// `(cm, mk)`.
    type Data = (note::Commitment, NoteMasterKey);

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, mk) = *data;
        (vec![Fp::from(cm), mk.0], Vec::new(), Vec::new(), Vec::new())
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(cm, epoch_start, nf_commit, epoch_end)`: covers epochs
/// `[epoch_start, epoch_end)`; `nf_commit` commits the range's nullifier
/// sequence as an [`NfSeqPoly`], exactly one member per covered epoch. That
/// invariant is established at [`NfDerive`], preserved by
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
pub struct NullifierDerivation;

impl Header for NullifierDerivation {
    /// `(cm, epoch_start, nf_commit, epoch_end)`. `epoch_end` is exclusive.
    type Data = (note::Commitment, EpochIndex, NfSeqCommit, EpochIndex);

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, epoch_start, nf_commit, epoch_end) = *data;
        (
            vec![Fp::from(cm), Fp::from(epoch_start), Fp::from(epoch_end)],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(nf_commit)],
        )
    }
}

/// Certify a note's commitment and master key.
///
/// Seed step. Witnesses the note and its proof authorizing key, proves the
/// key belongs to the note (`note.pk == pak.derive_payment_key()`, which pins
/// `nk`), derives `mk` from `nk` and the note's trapdoor, and computes `cm`.
/// `nk` never leaves the step; only `pk`, which preimage-hides it, enters
/// `cm`.
///
/// # Soundness
///
/// A seed can invent a note, so `cm` closes downstream, at
/// [`SpendableInit`](super::spendable::SpendableInit) and
/// [`SpendStamp`](super::stamp::SpendStamp). What this step establishes is
/// the pairing: `mk` is *this* `cm`'s master key.
#[derive(Debug)]
pub struct NfMasterSeed;

impl Step for NfMasterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NfMasterHeader;
    type Right = ();
    /// `(note, pak)`.
    type Witness<'source> = (Note, ProofAuthorizingKey);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, pak): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(note.pk) - Fp::from(pak.derive_payment_key()),
            "NfMasterSeed: pak not related to note",
        )?;
        let mk = pak.nk.derive_note_private(note.psi);
        let cm = note.commitment();
        Ok(((cm, mk), ()))
    }
}

/// Derive one window of nullifiers and export it as a
/// [`NullifierDerivation`].
///
/// `Left = NfMasterSeed`. Witnesses the window's start epoch (constrained
/// group-aligned, $w \bmod r = 0$ for $r$ the sponge rate `PoseidonFp::RATE`)
/// and the window sequence. Runs one sponge per group over
/// $(\mathtt{NF\_DOMAIN}, \mathsf{mk}, w)$, each absorbing three elements and
/// squeezing $r$ nullifiers for one permutation, then binds the sequence to
/// the window's members by a single opening at a free $z$ against their
/// natively encoded product.
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
pub struct NfDerive;

impl Step for NfDerive {
    type Aux<'source> = ();
    type Left = NfMasterHeader;
    type Output = NullifierDerivation;
    type Right = ();
    /// `(epoch_start, seq)`.
    type Witness<'source> = (EpochIndex, NfSeqPoly);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (epoch_start, seq): Self::Witness<'source>,
        (cm, mk): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        #[expect(
            clippy::as_conversions,
            clippy::integer_division_remainder_used,
            reason = "the group width is a small constant"
        )]
        enforce_zero(
            Fp::from(u64::from(epoch_start.0) % (PoseidonFp::RATE as u64)),
            "NfDerive: epoch_start is not group-aligned",
        )?;

        // NF_DERIVATION_WIDTH nullifiers, PoseidonFp::RATE per sponge.
        let nullifiers = mk.derive_window(epoch_start);

        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "constant length"
        )]
        let epoch_end = EpochIndex(epoch_start.0 + nullifiers.len() as u32);

        // `z`: a fresh transcript challenge over the sequence commitment. The
        // polynomial is fixed before it exists, so the single opening below
        // is not vacuous.
        let z = ctx.derive_challenge(&[seq.commit().into()])?;
        let seq_at_z = seq.eval(z);
        ctx.enforce_poly_query(seq.commit().into(), z, seq_at_z)?;

        // The window's members at `z`, encoded natively from the
        // sponge-derived nullifiers and their epochs.
        let window_at_z =
            indexed_multiset::direct_eval((epoch_start.into()..).zip(nullifiers.map(Fp::from)), z);

        enforce_zero(
            seq_at_z - window_at_z,
            "NfDerive: sequence does not match the derived window",
        )?;

        Ok(((cm, epoch_start, seq.commit(), epoch_end), ()))
    }
}

/// Merge two adjacent derived ranges into one (`left ++ right`).
///
/// Requires the same `cm` and contiguity (`right.epoch_start ==
/// left.epoch_end`). Witnesses the two range polynomials and their
/// concatenation, binds each by commit-equality, and proves the concat as the
/// product
///
/// $$\mathsf{merged}(X) = \mathsf{left}(X) \cdot \mathsf{right}(X)$$
///
/// since concatenation of disjoint ranges is exactly multiplication.
///
/// # Soundness
///
/// All three operands are committed and absorbed into the challenge, so the
/// product identity pins `merged`'s member multiset to the union of the
/// halves'. The contiguity check preserves the header invariant established
/// at the leaf: exactly one member per epoch in `[epoch_start, epoch_end)`,
/// so the announced range labels the member multiset truthfully.
#[derive(Debug)]
pub struct NullifierFuse;

impl Step for NullifierFuse {
    type Aux<'source> = ();
    type Left = NullifierDerivation;
    type Output = NullifierDerivation;
    type Right = NullifierDerivation;
    /// `(left_seq, merged_seq, right_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_seq, merged_seq, right_seq): Self::Witness<'source>,
        (left_cm, left_epoch_start, left_nf_commit, left_epoch_end): <Self::Left as Header>::Data,
        (right_cm, right_epoch_start, right_nf_commit, right_epoch_end): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_cm) - Fp::from(right_cm),
            "NullifierFuse: note commitments differ",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_end),
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
        let merged_nf_commit = merged_seq.commit();
        enforce_poly_product(
            ctx,
            left_seq.as_ref(),
            right_seq.as_ref(),
            merged_seq.as_ref(),
            "NullifierFuse: merged is not the concat of the halves",
        )?;
        Ok((
            (left_cm, left_epoch_start, merged_nf_commit, right_epoch_end),
            (),
        ))
    }
}
