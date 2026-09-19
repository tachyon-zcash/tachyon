//! Prove a fusable range of a note's per-epoch nullifiers.
//!
//! Three steps. [`NoteSeed`] certifies the note's commitment and master
//! key; [`NullifierDerive`] consumes that seed and exports one whole window;
//! and [`NullifierFuse`] concatenates adjacent windows.
//!
//! All headers are wallet-only, and no key material rides the exported
//! [`NoteNullifiers`].

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};
use ragu_arithmetic::PoseidonPermutation as _;
use ragu_pasta::PoseidonFp;

use crate::{
    collections::indexed_multiset,
    constants::EPOCH_MAX,
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::NF_DERIVATION_WIDTH,
    primitives::{EpochIndex, NfSeqCommit, NfSeqPoly},
    ragu_constraint::{enforce_equal_point, enforce_zero},
    relations::enforce::enforce_poly_product,
};

/// A note's certified record: its commitment, its opening, and its master key
/// (wallet-only).
///
/// `mk` is derived natively from the note's secrets and certified here, so
/// every consuming [`NullifierDerive`] threads a genuine master key without
/// re-witnessing the note. `note` is the opening `cm` commits to, carried so
/// [`SpendAction`](super::stamp::SpendAction) binds by one field equality
/// instead of recomputing the commitment.
///
/// Wallet-only, as every delegation header is: the opening must not reach the
/// published [`Stamp`](super::stamp::Stamp), and does not, since the action
/// steps emit only set commitments and an anchor.
#[derive(Clone, Debug)]
pub struct NoteMaster;

impl Header for NoteMaster {
    /// `(cm, note, mk)`.
    type Data = (note::Commitment, Note, NoteMasterKey);

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, note, mk) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(note.rcm),
                Fp::from(note.pk),
                Fp::from(u64::from(note.value)),
                Fp::from(note.psi),
                mk.0,
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(cm, epoch_first, nf_commit, epoch_last)`: covers epochs
/// `[epoch_first, epoch_last]`; `nf_commit` commits the range's nullifier
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

impl Header for NoteNullifiers {
    /// `(cm, epoch_first, nf_commit, epoch_last)`. `epoch_last` is inclusive.
    type Data = (note::Commitment, EpochIndex, NfSeqCommit, EpochIndex);

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, epoch_first, nf_commit, epoch_last) = *data;
        (
            vec![Fp::from(cm), Fp::from(epoch_first), Fp::from(epoch_last)],
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
/// [`SpendAction`](super::stamp::SpendAction). What this step establishes is
/// the pairing: `mk` is *this* `cm`'s master key.
#[derive(Debug)]
pub struct NoteSeed;

impl Step for NoteSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NoteMaster;
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
            "NoteSeed: pak not related to note",
        )?;
        let mk = pak.nk.derive_note_private(note.psi);
        let cm = note.commitment();
        Ok(((cm, note, mk), ()))
    }
}

/// Derive one window of nullifiers and export it as a
/// [`NoteNullifiers`].
///
/// `Left = NoteSeed`. Witnesses the window's start epoch (constrained
/// group-aligned, $w \bmod r = 0$ for $r$ the sponge rate `PoseidonFp::RATE`)
/// and the window sequence. Runs one sponge per group over
/// $(\texttt{Tachyon-NfDerive}, \mathsf{mk}, w)$, each absorbing three elements
/// and squeezing $r$ nullifiers for one permutation, then binds the sequence to
/// the window's members by a single opening at a free $z$ against their
/// natively encoded product.
///
/// # Soundness
///
/// `mk` is threaded from the left header, so it is the note's genuine master
/// key by PCD soundness. The opening's only free operand is the window
/// sequence, committed before $z$ exists.
///
/// `epoch_first` is a free witness constrained group-aligned, pinned by the
/// header it produces: it is emitted on the header directly, so every choice
/// is an honestly labelled window. (The alignment constraint
/// is a native remainder fed to `enforce_zero` under mock ragu; a real
/// circuit needs a low-bit decomposition of the witnessed epoch, since
/// $4q = e$ is always solvable in the field.)
///
/// The epoch indices need no absorbing into $z$, each being `epoch_first`
/// plus a circuit constant. The nullifier scalars are sponge outputs of the
/// threaded `mk`, pinned in-circuit, so the product identity alone forces
/// every member.
#[derive(Debug)]
pub struct NullifierDerive;

impl Step for NullifierDerive {
    type Aux<'source> = ();
    type Left = NoteMaster;
    type Output = NoteNullifiers;
    type Right = ();
    /// `(epoch_first, seq)`.
    type Witness<'source> = (EpochIndex, NfSeqPoly);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (epoch_first, seq): Self::Witness<'source>,
        (cm, _note, mk): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        #[expect(
            clippy::as_conversions,
            clippy::integer_division_remainder_used,
            reason = "the group width is a small constant"
        )]
        enforce_zero(
            Fp::from(u64::from(epoch_first) % (PoseidonFp::RATE as u64)),
            "NullifierDerive: epoch_first is not group-aligned",
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
        let epoch_last = u32::from(epoch_first)
            .checked_add(NF_DERIVATION_WIDTH as u32 - 1)
            .filter(|last| *last <= EPOCH_MAX)
            .map(EpochIndex::new)
            .ok_or_else(|| {
                ragu_core::Error::InvalidWitness(
                    "NullifierDerive: window exceeds the epoch range".into(),
                )
            })?;

        // NF_DERIVATION_WIDTH nullifiers, PoseidonFp::RATE per sponge.
        let nullifiers = mk.derive_window(epoch_first);

        // `z`: a fresh transcript challenge over the sequence commitment. The
        // polynomial is fixed before it exists, so the single opening below
        // is not vacuous.
        let z = ctx.derive_challenge(&[seq.commit().into()])?;
        let seq_at_z = seq.eval(z);
        ctx.enforce_poly_query(seq.commit().into(), z, seq_at_z)?;

        // The window's members at `z`, encoded natively from the
        // sponge-derived nullifiers and their epochs.
        let window_at_z =
            indexed_multiset::direct_eval((epoch_first.into()..).zip(nullifiers.map(Fp::from)), z);

        enforce_zero(
            seq_at_z - window_at_z,
            "NullifierDerive: sequence does not match the derived window",
        )?;

        Ok(((cm, epoch_first, seq.commit(), epoch_last), ()))
    }
}

/// Merge two adjacent derived ranges into one (`left ++ right`).
///
/// Requires the same `cm` and contiguity (`right.epoch_first ==
/// left.epoch_last + 1`). Witnesses the two range polynomials and their
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
/// at the leaf: exactly one member per epoch in `[epoch_first, epoch_last]`,
/// so the announced range labels the member multiset truthfully.
#[derive(Debug)]
pub struct NullifierFuse;

impl Step for NullifierFuse {
    type Aux<'source> = ();
    type Left = NoteNullifiers;
    type Output = NoteNullifiers;
    type Right = NoteNullifiers;
    /// `(left_seq, merged_seq, right_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_seq, merged_seq, right_seq): Self::Witness<'source>,
        (left_cm, left_epoch_first, left_nf_commit, left_epoch_last): <Self::Left as Header>::Data,
        (right_cm, right_epoch_first, right_nf_commit, right_epoch_last): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_cm) - Fp::from(right_cm),
            "NullifierFuse: note commitments differ",
        )?;
        enforce_zero(
            Fp::from(right_epoch_first) - Fp::from(left_epoch_last) - Fp::ONE,
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
            (
                left_cm,
                left_epoch_first,
                merged_nf_commit,
                right_epoch_last,
            ),
            (),
        ))
    }
}
