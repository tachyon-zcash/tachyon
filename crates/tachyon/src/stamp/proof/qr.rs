//! QR epoch evidence: one epoch's tachygrams partitioned by profile.
//!
//! Each depth classifies at a discriminant of the progression
//!
//! $$
//!   R_j = R_0 + j,
//! $$
//!
//! from a first discriminant $R_0$. Every header carries $R_0$, so depth $j$
//! classifies at $R_j$, and a value takes the residue side there iff $x + R_j$
//! is a square or zero.
//!
//! [`QrSummaryIntake`] starts a [`QrIntake`] from a [`Summary`],
//! [`QrStampIntakeSeed`] from one unsummarized stamp, and
//! [`QrEmptyIntakeSeed`] over an epoch with no stamps. [`QrIntakeSplit`]
//! partitions an intake at its discriminant into [`QrIntakeSides`],
//! [`QrSideDescend`] carries one side down a level, and [`QrIntakeMerge`]
//! joins two same-profile intakes whose spans meet. [`QrBucketSeal`] is the
//! only step that produces a [`QrBucket`], and [`QrUnspentInit`] tests a
//! value's profile against a bucket and opens the bucket at it.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};
use ragu_arithmetic::{Cycle as _, FixedGenerators as _};
use ragu_pasta::Pasta;

use super::{pool::ArbitraryUnspent, summary::Summary};
pub use crate::collections::qr::classify;
use crate::{
    collections::{indexed_multiset, qr::QUADRATIC_NON_RESIDUE},
    digest::poseidon,
    nullifier::Nullifier,
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrInterpolantPoly, QrProfile,
        QrQuotientPoly, Tachygram, TachygramSetCommit, TachygramSetPoly,
    },
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::enforce_poly_product,
};

/// Tachygrams under routing. Every member of `contents` takes `profile`, and
/// a split classifies at `discriminant.at(profile.depth)`. A builder keeps its
/// intake headers unpublished until the epoch closes.
#[derive(Clone, Debug)]
pub struct QrIntake;

impl Header for QrIntake {
    /// `(epoch, anchor_prev, anchor_end, discriminant, profile, contents)`.
    /// The contents were drawn from the folds the coverage extent
    /// `(anchor_prev, anchor_end]` certifies; `discriminant` is the network's
    /// $R_0$.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_end, discriminant, profile, contents) = *data;
        (
            vec![
                Fp::from(epoch),
                Fp::from(anchor_prev),
                Fp::from(anchor_end),
                Fp::from(discriminant),
                Fp::from(u64::from(profile.depth)),
                Fp::from(u64::from(profile.bits)),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(contents)],
        )
    }
}

/// One intake's members partitioned at its discriminant. Extracting either
/// side attests the other.
#[derive(Clone, Debug)]
pub struct QrIntakeSides;

impl Header for QrIntakeSides {
    /// `(epoch, anchor_prev, anchor_end, discriminant, profile, non_residue,
    /// residue)`, the fields of the intake that was split with its two sides
    /// in place of its contents. The sides are ordered by the bit that selects
    /// them: `0 = NQR, 1 = QR`.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_end, discriminant, profile, non_residue, residue) = *data;
        (
            vec![
                Fp::from(epoch),
                Fp::from(anchor_prev),
                Fp::from(anchor_end),
                Fp::from(discriminant),
                Fp::from(u64::from(profile.depth)),
                Fp::from(u64::from(profile.bits)),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(non_residue), Eq::from(residue)],
        )
    }
}

/// Start a root intake from a [`Summary`].
///
/// # Soundness
///
/// `discriminant` is a free witness; see [`QrDiscriminant`].
#[derive(Debug)]
pub struct QrSummaryIntake;

impl Step for QrSummaryIntake {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = QrIntake;
    type Right = ();
    /// `(discriminant)`
    type Witness<'source> = (QrDiscriminant,);

    const INDEX: Index = Index::new(21);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (discriminant,): Self::Witness<'source>,
        (summary_epoch, summary_anchor_prev, summary_anchor_end, summary_acc_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((
            (
                summary_epoch,
                summary_anchor_prev,
                summary_anchor_end,
                discriminant,
                QrProfile::ROOT,
                summary_acc_commit,
            ),
            (),
        ))
    }
}

/// Start a root intake from one stamp:
/// [`SummarySeed`](super::summary::SummarySeed) with a [`QrIntake`] output.
///
/// # Soundness
///
/// `discriminant` is a free witness; see [`QrDiscriminant`]. `stamp_commit`
/// is folded into `anchor_end`.
#[derive(Debug)]
pub struct QrStampIntakeSeed;

impl Step for QrStampIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    /// `(anchor_prev, epoch, discriminant, stamp_commit)`
    type Witness<'source> = (Anchor, EpochIndex, QrDiscriminant, TachygramSetCommit);

    const INDEX: Index = Index::new(27);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, epoch, discriminant, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let anchor_end = anchor_prev
            .next_stamp(epoch, &stamp_commit)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
        Ok((
            (
                epoch,
                anchor_prev,
                anchor_end,
                discriminant,
                QrProfile::ROOT,
                stamp_commit,
            ),
            (),
        ))
    }
}

/// Start a root intake over an epoch that published no stamp.
///
/// The intake runs from `anchor` to itself and holds nothing.
///
/// # Soundness
///
/// `anchor` and `epoch` are free witnesses. [`QrBucketSeal`] requires `anchor`
/// to have epoch-link form into `epoch` and crosses from it, so the sealed
/// bucket ends on the published entry anchor of `epoch + 1` only if `anchor`
/// is both the entry and the final anchor of `epoch`: only if the epoch
/// published no stamp. `discriminant` is a free witness; see
/// [`QrDiscriminant`].
#[derive(Debug)]
pub struct QrEmptyIntakeSeed;

impl Step for QrEmptyIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    /// `(anchor, epoch, discriminant)`
    type Witness<'source> = (Anchor, EpochIndex, QrDiscriminant);

    const INDEX: Index = Index::new(29);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor, epoch, discriminant): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((
            (
                epoch,
                anchor,
                anchor,
                discriminant,
                QrProfile::ROOT,
                TachygramSetCommit::default(),
            ),
            (),
        ))
    }
}

/// Join two same-profile intakes whose spans meet.
///
/// # Soundness
///
/// Both contents are pinned to their headers by commit-equality. Consensus
/// forbids republishing a tachygram within two epochs, so the sets are
/// disjoint and the product is the union's root polynomial.
#[derive(Debug)]
pub struct QrIntakeMerge;

impl Step for QrIntakeMerge {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntake;
    type Right = QrIntake;
    /// `(left_contents, right_contents, merged)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(22);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_contents, right_contents, merged): Self::Witness<'source>,
        (
            left_epoch,
            left_anchor_prev,
            left_anchor_end,
            left_discriminant,
            left_profile,
            left_commit,
        ): <Self::Left as Header>::Data,
        (
            right_epoch,
            right_anchor_prev,
            right_anchor_end,
            right_discriminant,
            right_profile,
            right_commit,
        ): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_epoch) - Fp::from(right_epoch),
            "QrIntakeMerge: inputs cover different epochs",
        )?;
        enforce_zero(
            Fp::from(left_discriminant) - Fp::from(right_discriminant),
            "QrIntakeMerge: inputs derive from different discriminants",
        )?;
        enforce_zero(
            Fp::from(u64::from(left_profile.depth)) - Fp::from(u64::from(right_profile.depth)),
            "QrIntakeMerge: inputs sit at different depths",
        )?;
        enforce_zero(
            Fp::from(u64::from(left_profile.bits)) - Fp::from(u64::from(right_profile.bits)),
            "QrIntakeMerge: inputs sit at different profiles",
        )?;
        enforce_zero(
            Fp::from(left_anchor_end) - Fp::from(right_anchor_prev),
            "QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
        )?;
        enforce_equal_point(
            Eq::from(left_contents.commit()),
            Eq::from(left_commit),
            "QrIntakeMerge: left contents do not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_contents.commit()),
            Eq::from(right_commit),
            "QrIntakeMerge: right contents do not match header",
        )?;
        enforce_poly_product(
            ctx,
            left_contents.as_ref(),
            right_contents.as_ref(),
            merged.as_ref(),
            "QrIntakeMerge: merged contents are not the union of the inputs",
        )?;

        Ok((
            (
                left_epoch,
                left_anchor_prev,
                right_anchor_end,
                left_discriminant,
                left_profile,
                merged.commit(),
            ),
            (),
        ))
    }
}

/// Partition an intake's members at its own discriminant.
///
/// # Soundness
///
/// The product pins the two sides to a factorization of the contents;
/// [`QrSideDescend`] attests each child's sibling. The exceptional value $-R$
/// has root $0$ under either class, so the non-residue side must open nonzero
/// there.
#[derive(Debug)]
pub struct QrIntakeSplit;

impl Step for QrIntakeSplit {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntakeSides;
    type Right = ();
    /// `(contents, non_residue, residue)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(23);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (contents, non_residue, residue): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_end, discriminant, profile, contents_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(contents.commit()),
            Eq::from(contents_commit),
            "QrIntakeSplit: contents do not match header",
        )?;
        enforce_poly_product(
            ctx,
            non_residue.as_ref(),
            residue.as_ref(),
            contents.as_ref(),
            "QrIntakeSplit: the sides do not partition the contents",
        )?;

        let exceptional = -discriminant.at(profile.depth);
        let non_residue_at_exceptional = non_residue.eval(exceptional);
        ctx.enforce_poly_query(
            non_residue.commit().into(),
            exceptional,
            non_residue_at_exceptional,
        )?;
        enforce_nonzero(
            non_residue_at_exceptional,
            "QrIntakeSplit: exceptional value claimed the non-residue class",
        )?;

        Ok((
            (
                epoch,
                anchor_prev,
                anchor_end,
                discriminant,
                profile,
                non_residue.commit(),
                residue.commit(),
            ),
            (),
        ))
    }
}

/// Extract one side of a partition and carry it down one level, attesting
/// the other side's class.
///
/// With $s$ the sibling, $u$ its interpolant and $h$ the quotient,
///
/// $$
///   u(X)^2 - c \cdot (X + R) = s(X) \cdot h(X)
/// $$
///
/// at the sibling's class $c$ holds only if every root of $s$ takes that
/// side at $R$, since each root leaves $u(x)^2 = c \cdot (x + R)$. With the
/// split's product, every member of the extracted class is then in the
/// child.
///
/// # Soundness
///
/// The sibling is pinned to its header commitment; the challenge absorbs the
/// sibling, interpolant and quotient commitments and $R$. $R$ is prover-chosen,
/// so without it a prover could solve the identity for $R$ after $z$. Every
/// root of the sibling then satisfies $u(x)^2 = c \cdot (x + R)$ at the
/// sibling's class $c$, and the split's product places every member of the
/// other class in the child. The child may hold a stray member of the
/// sibling's class; consumers open it nonzero, so a stray member cannot pass a
/// value that is present. $R$ is read off the header, so a descent classifies
/// at the same $R_0$ as every other step of the network. The parent's depth is
/// checked below [`QrProfile::MAX_DEPTH`], so `bits` stays below $2^{32}$ and
/// one depth's paths have distinct profiles.
#[derive(Debug)]
pub struct QrSideDescend;

impl Step for QrSideDescend {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrIntake;
    type Right = ();
    /// `(bit, sibling_contents, interpolant, quotient)`
    type Witness<'source> = (bool, TachygramSetPoly, QrInterpolantPoly, QrQuotientPoly);

    const INDEX: Index = Index::new(24);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (bit, sibling_contents, interpolant, quotient): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_end, discriminant, profile, non_residue, residue): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // TODO: a real circuit needs a bit decomposition of `depth` here; mock
        // ragu accepts the native comparison.
        if profile.depth >= u32::BITS {
            return Err(ragu_core::Error::InvalidWitness(
                "QrSideDescend: profile has no bit left for another side".into(),
            ));
        }

        // TODO: a real circuit must constrain `bit` boolean; the type carries it
        // under mock ragu.
        // TODO: select point coordinates in the real circuit. These native group
        // selectors produce identity intermediates when the commitments agree or
        // `bit` is false, which Ragu's nonidentity point gadgets cannot represent.
        let sibling_commit = sibling_contents.commit();
        let sibling = Eq::from(residue)
            + ((Eq::from(non_residue) - Eq::from(residue)) * Fp::from(u64::from(bit)));
        enforce_equal_point(
            Eq::from(sibling_commit),
            sibling,
            "QrSideDescend: sibling does not match the header",
        )?;
        let selected = Eq::from(non_residue)
            + ((Eq::from(residue) - Eq::from(non_residue)) * Fp::from(u64::from(bit)));

        let interpolant_commit = interpolant.commit();
        let quotient_commit = quotient.commit();
        let z = ctx.derive_challenge(&[
            sibling_commit.into(),
            interpolant_commit.into(),
            quotient_commit.into(),
            {
                // The mock absorbs only points, so absorb `[R]·G_0`.
                #[expect(clippy::expect_used, reason = "constant size")]
                let &g0 = Pasta::host_generators(Pasta::baked())
                    .g()
                    .first()
                    .expect("at least one generator");
                g0 * discriminant.at(profile.depth)
            },
        ])?;
        let sibling_at_z = sibling_contents.eval(z);
        let interpolant_at_z = interpolant.eval(z);
        let quotient_at_z = quotient.eval(z);
        ctx.enforce_poly_query(sibling_commit.into(), z, sibling_at_z)?;
        ctx.enforce_poly_query(interpolant_commit.into(), z, interpolant_at_z)?;
        ctx.enforce_poly_query(quotient_commit.into(), z, quotient_at_z)?;
        let shifted = z + discriminant.at(profile.depth);
        let class_residual = interpolant_at_z.square() - (sibling_at_z * quotient_at_z);
        let sibling_multiplier =
            Fp::ONE + ((QUADRATIC_NON_RESIDUE - Fp::ONE) * Fp::from(u64::from(bit)));
        enforce_zero(
            class_residual - (sibling_multiplier * shifted),
            "QrSideDescend: the sibling fails its class decomposition",
        )?;

        Ok((
            (
                epoch,
                anchor_prev,
                anchor_end,
                discriminant,
                profile.descend(bit),
                TachygramSetCommit::from(selected),
            ),
            (),
        ))
    }
}

/// One profile's members over a whole epoch.
///
/// [`QrBucketSeal`] gives both ends epoch-link form. `anchor_prev` absorbs
/// `epoch`, and `anchor_end` absorbs `epoch + 1`; the seal folds it from the
/// output of the bucket's last stamp fold. The bucket covers
/// `(anchor_prev, anchor_end]`, boundary to boundary.
#[derive(Clone, Debug)]
pub struct QrBucket;

impl Header for QrBucket {
    /// `(epoch, anchor_prev, anchor_end, discriminant, profile, contents)`
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_end, discriminant, profile, contents) = *data;
        (
            vec![
                Fp::from(epoch),
                Fp::from(anchor_prev),
                Fp::from(anchor_end),
                Fp::from(discriminant),
                Fp::from(u64::from(profile.depth)),
                Fp::from(u64::from(profile.bits)),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(contents)],
        )
    }
}

/// Seal a routed [`QrIntake`] into a [`QrBucket`] that runs boundary to
/// boundary.
///
/// The extent's `anchor_prev` must be the epoch link of `anchor_final_prev`
/// into `epoch`, and the step performs the boundary digest of the intake's
/// `anchor_end` into `epoch + 1`, emitting that as the bucket's
/// `anchor_end`.
///
/// # Soundness
///
/// Only an epoch link produces an anchor in the epoch domain, so an
/// `anchor_prev` of this form absorbs `epoch`. Whether it is the *entry
/// anchor* of `epoch` depends on what was published, and this step does not
/// check it: `anchor_final_prev` is a free witness, and the lineage that
/// consumes the bucket binds it. [`Anchor::default`] is epoch zero's
/// entry anchor and follows this rule at an `anchor_final_prev` of zero.
///
/// The crossing is what makes the bucket's whole-epoch claim true. In the
/// accepted chain, the only anchor of epoch-link form absorbing `epoch + 1` is
/// the one folded from `final(epoch)`. This step emits
/// `H_epoch(a, epoch + 1)` for the intake's own `a`, so if `a` is not
/// `final(epoch)` the result is on no chain, and by preimage resistance
/// neither is any fold downstream of it. A bucket sealed short of the epoch
/// therefore yields evidence no lineage can carry to a consensus-checked spend.
///
/// `discriminant` is prover-chosen and unchecked here; see [`QrDiscriminant`].
#[derive(Debug)]
pub struct QrBucketSeal;

impl Step for QrBucketSeal {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrBucket;
    type Right = ();
    /// `(anchor_final_prev)`
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(26);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_final_prev,): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_end, discriminant, profile, contents): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(anchor_prev)
                - poseidon::anchor_next_epoch(Fp::from(anchor_final_prev), Fp::from(epoch)),
            "QrBucketSeal: intake's first anchor is not an epoch link into its epoch",
        )?;
        let epoch_next = epoch.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness("QrBucketSeal: crossing past the final epoch".into())
        })?;
        let crossing = anchor_end
            .next_epoch(epoch_next)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

        Ok((
            (
                epoch,
                anchor_prev,
                crossing,
                discriminant,
                profile,
                contents,
            ),
            (),
        ))
    }
}

/// Start an [`ArbitraryUnspent`] from a [`QrBucket`].
///
/// The step fixes the value's side at every discriminant of the epoch, matches
/// the bucket's profile against the first `depth` of them, and opens the
/// bucket at the value for nonzero. The `MAX_DEPTH` positions
/// $j = 0, 1, \dots$ index the progression, so position $j$
/// classifies at $R_j = R_0 + j$. With $x$ the value and $s_j = x +
/// R_0 + j$, each position witnesses a side $b_j$ and a root $r_j$ with
///
/// $$
///   r_j^2 = \bigl(c - (c - 1) \cdot b_j\bigr) \cdot s_j,
///   \qquad
///   b_j = 0 \implies s_j \neq 0.
/// $$
///
/// A mask $m_j$ selects the bucket's path through two sums and a fold,
///
/// $$
///   \sum_j m_j = \mathsf{depth},
///   \qquad
///   \sum_j j \cdot m_j = \frac{\mathsf{depth} \cdot (\mathsf{depth} - 1)}{2},
///   \qquad
///   a_{j+1} = a_j + m_j \cdot (a_j + b_j),
/// $$
///
/// with $a_0 = 0$; the fold ends at $\mathsf{bits}$ exactly when the
/// bucket's sides are the value's.
///
/// The emitted segment reads the value as a nullifier and takes the bucket's
/// extent, which ends on the boundary into `epoch + 1`. Stepping onto that
/// boundary enters a new epoch, so the step also witnesses the next epoch's
/// nullifier, and the segment covers `[epoch, epoch + 1]` in epoch space.
/// Consecutive epochs' segments therefore meet at the entry anchor and fuse
/// directly.
///
/// # Soundness
///
/// $c$ is a non-residue, so for $s_j \neq 0$ exactly one of $s_j$, $c \cdot
/// s_j$ is a square and $b_j$ is the value's side. For $s_j = 0$ the nonzero
/// rule forces the residue side, where [`QrIntakeSplit`] files the exceptional
/// value. Among boolean vectors of weight `depth` only the leading positions
/// attain index sum $\mathsf{depth} \cdot (\mathsf{depth} - 1)/2$, so the mask
/// is that prefix and `depth` is at most [`QrProfile::MAX_DEPTH`]. The fold
/// then equals `bits` iff the bucket's sides are the value's first `depth`
/// sides. Positions past `depth` are tested but compared to nothing. $R_0$ is
/// the bucket's own `discriminant`, so the exclusion holds for the network
/// the bucket belongs to. `value` and `nf_next` are free witnesses. The
/// challenge absorbs both, so the sequence identity fixes both, and the
/// emitted boundary pairs are the sequence's own members;
/// [`UnspentBind`](super::pool::UnspentBind) forces each against the note's
/// genuine derivation.
///
/// [`QrBucketSeal`] performs the boundary digest, and so establishes
/// whole-epoch coverage. This step and every fuse and lift preserve it.
#[derive(Debug)]
pub struct QrUnspentInit;

impl Step for QrUnspentInit {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(value, nf_next, classes, mask, sequence, contents)`
    type Witness<'source> = (
        Tachygram,
        Nullifier,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(25);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (value, nf_next, classes, mask, sequence, contents): Self::Witness<'source>,
        (
            bucket_epoch,
            bucket_anchor_prev,
            bucket_anchor_end,
            discriminant,
            profile,
            contents_commit,
        ): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(contents.commit()),
            Eq::from(contents_commit),
            "QrUnspentInit: contents do not match the bucket",
        )?;
        enforce_nonzero(Fp::from(value), "QrUnspentInit: tested value is zero")?;
        enforce_nonzero(
            Fp::from(nf_next),
            "QrUnspentInit: next-epoch nullifier is zero",
        )?;

        // TODO: a real circuit must constrain every side and mask bit boolean;
        // the types carry it under mock ragu.
        let mut shifted = Fp::from(value) + Fp::from(discriminant);
        let mut position_fp = Fp::ZERO;
        let mut depth_acc = Fp::ZERO;
        let mut index_acc = Fp::ZERO;
        let mut bits_acc = Fp::ZERO;
        for (&QrClassRoot(side, root), &selected) in classes.iter().zip(&mask) {
            let side_fp = Fp::from(u64::from(side));
            let multiplier = QUADRATIC_NON_RESIDUE - ((QUADRATIC_NON_RESIDUE - Fp::ONE) * side_fp);
            enforce_zero(
                root.square() - (multiplier * shifted),
                "QrUnspentInit: root does not square to the claimed class",
            )?;
            enforce_nonzero(
                (shifted * (Fp::ONE - side_fp)) + side_fp,
                "QrUnspentInit: exceptional discriminant claimed the non-residue class",
            )?;

            let selected_fp = Fp::from(selected);
            depth_acc += selected_fp;
            index_acc += selected_fp * position_fp;
            bits_acc += selected_fp * (bits_acc + side_fp);
            shifted += Fp::ONE;
            position_fp += Fp::ONE;
        }
        enforce_zero(
            depth_acc - Fp::from(u64::from(profile.depth)),
            "QrUnspentInit: depth mask does not match the bucket's depth",
        )?;
        enforce_zero(
            index_acc.double() - (depth_acc * (depth_acc - Fp::ONE)),
            "QrUnspentInit: depth mask is not a prefix",
        )?;
        enforce_zero(
            bits_acc - Fp::from(u64::from(profile.bits)),
            "QrUnspentInit: value does not take the bucket's profile",
        )?;

        let epoch_next = bucket_epoch.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness("QrUnspentInit: bucket has no next epoch".into())
        })?;

        let sequence_commit = sequence.commit();
        let z = ctx.derive_challenge(&[
            sequence_commit.into(),
            {
                // The mock absorbs only points, so absorb `[value]·G_0`.
                #[expect(clippy::expect_used, reason = "constant size")]
                let &g0 = Pasta::host_generators(Pasta::baked())
                    .g()
                    .first()
                    .expect("at least one generator");
                g0 * Fp::from(value)
            },
            {
                // The mock absorbs only points, so absorb `[nf_next]·G_0`.
                #[expect(clippy::expect_used, reason = "constant size")]
                let &g0 = Pasta::host_generators(Pasta::baked())
                    .g()
                    .first()
                    .expect("at least one generator");
                g0 * Fp::from(nf_next)
            },
        ])?;
        let sequence_at_z = sequence.eval(z);
        ctx.enforce_poly_query(sequence_commit.into(), z, sequence_at_z)?;

        let crossing_at_z = indexed_multiset::direct_eval(
            [
                (u64::from(bucket_epoch), value.into()),
                (u64::from(epoch_next), Fp::from(nf_next)),
            ],
            z,
        );
        enforce_zero(
            sequence_at_z - crossing_at_z,
            "QrUnspentInit: sequence does not match the crossing pairs",
        )?;

        let contents_at_value = contents.eval(value.into());
        ctx.enforce_poly_query(contents_commit.into(), value.into(), contents_at_value)?;
        enforce_nonzero(
            contents_at_value,
            "QrUnspentInit: found nullifier in the bucket",
        )?;

        Ok((
            (
                bucket_anchor_prev,
                (bucket_epoch, Nullifier::from(value)),
                sequence_commit,
                (epoch_next, nf_next),
                bucket_anchor_end,
            ),
            (),
        ))
    }
}
