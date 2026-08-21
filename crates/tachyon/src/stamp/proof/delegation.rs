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
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use crate::{
    digest::poseidon::{self, NF_GROUP},
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::{NF_DERIVATION_GROUPS, NF_DERIVATION_WIDTH, Nullifier},
    primitives::{EpochGroup, EpochIndex, NfSeqCommit, NfSeqPoly},
    relations::enforce::enforce_shifted_combination,
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
/// `(cm, (epoch_start, nf_start), nf_commit, (epoch_end, nf_last))`: covers
/// epochs `[epoch_start, epoch_end)`; `nf_commit` commits the range's
/// nullifier sequence $g$ in bare Horner order (see
/// [`NfSeqPoly`]), one coefficient per covered
/// epoch, the newest at degree $0$. `cm` binds the range to the real note.
///
/// No consumer reads either boundary nullifier as data; every read selects
/// its own window out of the sequence. `nf_start` is the **rank pin**: it is
/// $g$'s top coefficient, nonzero by the leaf's guards and threaded by the
/// fuse, and that induction is what places every covering read's bands.
/// `nf_last` is pinned by the fuse's degree-0 query.
///
/// The header carries a range and a commitment, nothing about who will read
/// it or where: masking is the consuming step's responsibility.
#[derive(Clone, Debug)]
pub struct NullifierDerivation;

impl Header for NullifierDerivation {
    /// `(cm, (epoch_start, nf_start), nf_commit, (epoch_end, nf_last))`.
    /// `epoch_end` is exclusive and names no item; `nf_last` is the member at
    /// `epoch_end - 1`.
    type Data = (
        note::Commitment,
        (EpochIndex, Nullifier),
        NfSeqCommit,
        (EpochIndex, Nullifier),
    );

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, (epoch_start, nf_start), nf_commit, (epoch_end, nf_last)) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(epoch_start),
                Fp::from(nf_start),
                Fp::from(epoch_end),
                Fp::from(nf_last),
            ],
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
/// `Left = NfMasterSeed`. Witnesses the window's [`EpochGroup`] and the
/// window sequence $g$. Runs `NF_DERIVATION_GROUPS` sponges over
/// $(\mathtt{NF\_DOMAIN}, \mathsf{mk}, w)$, each absorbing three elements and
/// squeezing `NF_GROUP` nullifiers for one permutation, then binds $g$ to the
/// window's members by a single opening at a free $z$ against their bare
/// Horner accumulation
///
/// $$g(z) = \sum_{j < W} \mathsf{nf}_{\mathsf{base}+j}\, z^{\,W-1-j}$$
///
/// for $W$ = `NF_DERIVATION_WIDTH`. Because $z$ is free and both sides have
/// degree below $W$, the single opening forces every coefficient of $g$ to
/// the genuine nullifier, and the boundary members are emitted on the header
/// as derived values.
///
/// # Group alignment
///
/// The witness carries the window's group $w_0$ and the step derives
/// $\mathsf{base} = \mathsf{NF\_GROUP} \cdot w_0$, which makes the sponge
/// count a circuit constant: `NF_DERIVATION_GROUPS` permutations. The export
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
/// `group` is witnessed and otherwise unbound, and needs no further binding:
/// $\mathsf{base} = \mathsf{NF\_GROUP} \cdot w_0$ is injective, so the emitted
/// bounds determine $w_0$ and hence the sponge inputs. A prover choosing a
/// different group gets a correct window for a different span, honestly
/// labelled, and one past [`EpochGroup::MAX`] labels epochs that do not
/// exist. The window-wide nonzero guard doubles as the rank pin: `nf_start` is
/// $g$'s top coefficient and cannot be zero, so the announced span is the
/// exact rank.
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
        (group, seq): Self::Witness<'source>,
        (cm, mk): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Native stand-in for the base check. `base` is the product
        // `NF_GROUP * group`, so alignment needs no check of its own.
        if group > EpochGroup::MAX {
            return Err(ragu::Error::InvalidWitness(
                "NfDerive: base exceeds epoch space".into(),
            ));
        }
        let base = group.start_epoch();

        // The window's nullifiers, `NF_GROUP` per permutation. `mk` is
        // threaded, so these are the note's genuine nullifiers.
        let mut nullifiers = [Fp::ZERO; NF_DERIVATION_WIDTH];
        for sponge in 0..NF_DERIVATION_GROUPS {
            #[expect(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                reason = "the group count is a small constant"
            )]
            let squeezed = poseidon::nullifier_group(mk.0, EpochGroup(group.0 + sponge as u32));
            for (slot, value) in squeezed.into_iter().enumerate() {
                #[expect(
                    clippy::indexing_slicing,
                    reason = "constant widths, indexing the window this loop fills"
                )]
                {
                    nullifiers[sponge * NF_GROUP + slot] = value;
                }
            }
        }

        // Window-wide nonzero guard: a nonzero `nf_start` is the sequence's
        // rank pin.
        for &nf in &nullifiers {
            enforce_nonzero(nf, "NfDerive: derived nullifier is zero")?;
        }

        // `z`: a fresh transcript challenge over the sequence commitment. The
        // polynomial is fixed before it exists, so the single opening below
        // is not vacuous.
        let z = ctx.derive_challenge(&[seq.commit().into()])?;
        let seq_at_z = seq.eval(z);
        ctx.enforce_poly_query(seq.commit().into(), z, seq_at_z)?;

        // Horner-accumulate the window's squeezes at `z`, oldest first: both
        // sides have degree below the window width, so equality at a free
        // point forces every coefficient of the committed sequence.
        let mut accumulated = Fp::ZERO;
        for &nf in &nullifiers {
            accumulated = accumulated * z + nf;
        }

        enforce_zero(
            seq_at_z - accumulated,
            "NfDerive: sequence does not match the derived window",
        )?;

        let (nf_start, nf_last) = (
            Nullifier::from(nullifiers[0]),
            Nullifier::from(nullifiers[NF_DERIVATION_WIDTH - 1]),
        );
        Ok((
            (
                cm,
                (base, nf_start),
                seq.commit(),
                (group.end_epoch(), nf_last),
            ),
            (),
        ))
    }
}

/// Merge two adjacent derived ranges into one (`left ++ right`).
///
/// Requires the same `cm` and contiguity (`right.epoch_start ==
/// left.epoch_end`). Witnesses the two range polynomials and their
/// concatenation, binds each by commit-equality, and proves the concat as the
/// bare Horner shift: a sequence of $k$ members is $\sum n_i X^{k-1-i}$ and
/// no member is shared across the seam, so
///
/// $$\mathsf{merged}(X) = X^{k_R}\,\mathsf{left}(X) + \mathsf{right}(X),$$
///
/// with the member count $k_R$ fixed by right's header span: bare Horner
/// concatenation is exactly the shifted sum.
///
/// # Soundness
///
/// The degree-0 queries pin the *end* nullifiers, the only coefficients a
/// single opening isolates under Horner order: `merged` opens to
/// `right.nf_last` (also right's own degree 0) and `left` opens to
/// `left.nf_last`. `nf_start` is the
/// non-extractable top coefficient; it threads from the left header, and its
/// nonzero-ness (the rank pin) is inductive from the leaf's cover-wide guard.
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
        (
            left_cm,
            (left_epoch_start, left_nf_start),
            left_nf_commit,
            (left_epoch_end, left_nf_last),
        ): <Self::Left as Header>::Data,
        (
            right_cm,
            (right_epoch_start, _right_nf_start),
            right_nf_commit,
            (right_epoch_end, right_nf_last),
        ): <Self::Right as Header>::Data,
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
        let right_span = right_epoch_end - right_epoch_start;
        enforce_shifted_combination(
            ctx,
            [
                (left_seq.as_ref(), right_span.into()),
                (right_seq.as_ref(), 0),
            ],
            [],
            merged_seq.as_ref(),
            "NullifierFuse: merged is not the concat of the halves",
        )?;
        ctx.enforce_poly_query(merged_nf_commit.into(), Fp::ZERO, Fp::from(right_nf_last))?;
        ctx.enforce_poly_query(left_seq.commit().into(), Fp::ZERO, Fp::from(left_nf_last))?;
        Ok((
            (
                left_cm,
                (left_epoch_start, left_nf_start),
                merged_nf_commit,
                (right_epoch_end, right_nf_last),
            ),
            (),
        ))
    }
}
