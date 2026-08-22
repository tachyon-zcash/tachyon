//! Prove a fusable range of a note's per-epoch nullifiers.
//!
//! Three steps. [`NfMasterSeed`] witnesses the note once and certifies its
//! commitment and master key; [`NfDerive`] consumes that seed as often as
//! the wallet needs windows, exporting one whole window per proof; and
//! [`NullifierFuse`] concatenates adjacent windows, so a span of any length
//! is a chain of them.
//! All headers are wallet-only, and no key material rides the exported
//! [`NullifierDerivation`].

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Header, Index, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};

use crate::{
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    primitives::{EpochGroup, EpochIndex, NF_FACTOR_RESIDUE, NfSeqCommit, NfSeqPoly},
    relations::enforce::enforce_poly_product,
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
/// sequence as the factor product (see [`NfSeqPoly`]), **exactly one factor
/// per covered epoch**, each factor carrying its own epoch index — a
/// provenance invariant established at [`NfDerive`] and preserved by
/// [`NullifierFuse`]'s contiguity check, and what the divisibility binds
/// lean on for per-epoch completeness. `cm` binds the range to the real
/// note.
///
/// No consumer reads the range: each factor carries its own epoch, so a read
/// concludes coverage from divisibility rather than comparing bounds. The
/// range is here for [`NullifierFuse`]'s contiguity check, which is what keeps
/// the product squarefree — and squarefreeness is what forces a tested
/// sequence's factors distinct at
/// [`UnspentBind`](super::pool::UnspentBind).
///
/// The header carries a range and a commitment, nothing about who will read
/// it or where: masking is the consuming step's responsibility.
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
/// A seed can invent a note, so `cm` proves nothing on its own. It closes
/// downstream, where
/// [`SpendableInit`](super::spendable::SpendableInit) binds it to
/// creation-set membership and
/// [`SpendStamp`](super::stamp::SpendStamp) re-derives it from the spent
/// note. What this step does establish is that `mk` is *this* `cm`'s master
/// key, and PCD soundness carries that pairing into every consuming
/// [`NfDerive`].
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
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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
/// `Left = NfMasterSeed`. Witnesses the window's [`EpochGroup`] and the window
/// sequence. Runs one sponge per group over
/// $(\mathtt{NF\_DOMAIN}, \mathsf{mk}, w)$, each absorbing three elements and
/// squeezing `NF_DERIVATION_GROUP` nullifiers for one permutation, then binds
/// the sequence to the window's members by a single opening at a free $z$
/// against the native product of the window's factors
///
/// $$\mathsf{seq}(z) = \prod_{j < W} F_{\mathsf{base}+j,\
/// \mathsf{nf}_{\mathsf{base}+j}}(z)$$
///
/// for $W$ = `NF_DERIVATION_WIDTH`. The sequence is committed and absorbed
/// before $z$ exists and the factor scalars are pinned (see soundness), so the
/// identity forces it to exactly the product of the genuine factors.
///
/// # Group alignment
///
/// The witness carries the window's group $w_0$ and the step derives
/// $\mathsf{base} = \mathsf{NF\_DERIVATION\_GROUP} \cdot w_0$, which makes the
/// sponge count a circuit constant, one permutation each. The export
/// is the whole window, so its bounds are derived rather than witnessed and a
/// span of any length is a fused chain of windows ([`NullifierFuse`]).
/// Consumers accept any derivation *covering* the epochs they read, so none of
/// them sees the alignment.
///
/// # Soundness
///
/// `mk` is threaded from the left header, so it is the note's genuine master
/// key by PCD soundness. The nullifiers are derived natively from it and
/// certified into `nf_commit` by the opening, whose only free operand is the
/// window sequence, committed before $z$ exists.
///
/// `group` is a free witness, pinned by the header it produces: $\mathsf{base}
/// = \mathsf{NF\_DERIVATION\_GROUP} \cdot w_0$ is injective, so the emitted
/// epoch determines $w_0$ and hence the sponge inputs, and every choice is an
/// honestly labelled window.
///
/// The epoch indices enter the factors natively without being absorbed into
/// $z$, and need no absorbing: each is $\mathsf{base}$ plus a circuit
/// constant, so none of them is free. The nullifier scalars are sponge outputs
/// of the threaded `mk`, pinned in-circuit, so the product identity alone
/// forces every factor.
#[derive(Debug)]
pub struct NfDerive;

impl Step for NfDerive {
    type Aux<'source> = ();
    type Left = NfMasterHeader;
    type Output = NullifierDerivation;
    type Right = ();
    /// `(group, seq)`.
    type Witness<'source> = (EpochGroup, NfSeqPoly);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (group_start, seq): Self::Witness<'source>,
        (cm, mk): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // NF_DERIVATION_WIDTH nullifiers from NF_DERIVATION_GROUP sponges.
        let nullifiers = mk.derive_window(group_start);

        let epoch_start = group_start.start_epoch();
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

        // The window's factor product at `z`, each factor evaluated natively
        // from the sponge-derived member and its epoch.
        let mut accumulated = Fp::ONE;
        for (offset, nf) in nullifiers.into_iter().enumerate() {
            #[expect(clippy::as_conversions, reason = "the window is a constant width")]
            let linear = Fp::from(u64::from(epoch_start.0) + 1 + offset as u64) * z + Fp::from(nf);
            accumulated *= linear.square() * linear - NF_FACTOR_RESIDUE;
        }

        enforce_zero(
            seq_at_z - accumulated,
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
/// factor product
///
/// $$\mathsf{merged}(X) = \mathsf{left}(X) \cdot \mathsf{right}(X):$$
///
/// under the factor encoding, concatenation of disjoint ranges is exactly
/// multiplication.
///
/// # Soundness
///
/// All three operands are committed and absorbed into the challenge, so the
/// product identity pins `merged`'s factor multiset to the union of the
/// halves'. The contiguity check preserves the header invariant established
/// at the leaf: exactly one factor per epoch in `[epoch_start, epoch_end)`,
/// so the announced range labels the factor multiset truthfully. The
/// product identity is confirmed a second time at the fixed point $0$.
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
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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
        // The same product identity at the fixed point 0.
        let (left_at_zero, right_at_zero, merged_at_zero) = (
            left_seq.eval(Fp::ZERO),
            right_seq.eval(Fp::ZERO),
            merged_seq.eval(Fp::ZERO),
        );
        enforce_zero(
            merged_at_zero - left_at_zero * right_at_zero,
            "NullifierFuse: merged constant term is not the product of the halves'",
        )?;
        ctx.enforce_poly_query(left_seq.commit().into(), Fp::ZERO, left_at_zero)?;
        ctx.enforce_poly_query(right_seq.commit().into(), Fp::ZERO, right_at_zero)?;
        ctx.enforce_poly_query(merged_nf_commit.into(), Fp::ZERO, merged_at_zero)?;
        Ok((
            (left_cm, left_epoch_start, merged_nf_commit, right_epoch_end),
            (),
        ))
    }
}
