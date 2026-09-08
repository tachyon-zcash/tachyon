//! QR epoch evidence: one epoch's tachygrams partitioned by profile.
//!
//! Each depth classifies at a discriminant of the progression
//!
//! $$
//!   R_{j+1} = R_j + 1
//! $$
//!
//! from an $R_1$ the routing prover derives from entropy of its choice and
//! every header carries. A value takes the residue side at depth $j$ iff
//! $x + R_j$ is a square or zero.
//!
//! [`QrSummaryIntakeInit`] starts a [`QrIntake`] from a [`Summary`], and
//! [`QrStampIntakeSeed`] from one unsummarized stamp. [`QrIntakeSplit`]
//! partitions an intake at its discriminant into [`QrIntakeSides`],
//! [`QrSideDescend`] carries one side down a level, and [`QrIntakeMerge`]
//! joins two same-profile intakes whose spans meet. [`QrBucketSeal`] is the
//! only step that produces a [`QrBucket`], and [`QrUnspentInit`] tests a
//! value's profile against a bucket and opens the bucket at it.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

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
    relations::enforce::enforce_poly_product,
};

/// Tachygrams under routing. Every member of `contents` takes `profile`, and
/// a split classifies at `discriminant.at(profile.depth)`.
#[derive(Clone, Debug)]
pub struct QrIntake;

impl Header for QrIntake {
    /// `(epoch, anchor_prev, anchor_last, discriminant, profile, contents)`.
    /// `anchor_prev` and `anchor_last` bracket the anchor links the contents
    /// were drawn from; `discriminant` is the epoch's $R_1$.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, discriminant, profile, contents) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
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
    /// `(epoch, anchor_prev, anchor_last, discriminant, profile, residue,
    /// non_residue)`, the fields of the intake that was split with its two
    /// sides in place of its contents.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, discriminant, profile, residue, non_residue) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
                Fp::from(discriminant),
                Fp::from(u64::from(profile.depth)),
                Fp::from(u64::from(profile.bits)),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(residue), Eq::from(non_residue)],
        )
    }
}

/// Start a root intake from a [`Summary`].
///
/// # Soundness
///
/// The entropy is the prover's choice; $R_1$ is its digest under
/// `Tachyon-QrDiscrm`. A consumer reads $R_1$ off the bucket.
#[derive(Debug)]
pub struct QrSummaryIntakeInit;

impl Step for QrSummaryIntakeInit {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = QrIntake;
    type Right = ();
    /// `(discriminant_entropy)`.
    type Witness<'source> = (Fp,);

    const INDEX: Index = Index::new(21);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (discriminant_entropy,): Self::Witness<'source>,
        (summary_epoch, summary_anchor_prev, summary_anchor_last, summary_acc_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let discriminant = poseidon::qr_discriminant(discriminant_entropy);
        Ok((
            (
                summary_epoch,
                summary_anchor_prev,
                summary_anchor_last,
                QrDiscriminant::from(discriminant),
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
/// The entropy is the prover's choice and $R_1$ its digest, as at
/// [`QrSummaryIntakeInit`]. `stamp_commit` is folded into `anchor_last`, and
/// the span binds through the lineage that consumes it.
#[derive(Debug)]
pub struct QrStampIntakeSeed;

impl Step for QrStampIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    /// `(anchor_prev, epoch, discriminant_entropy, stamp_commit)`.
    type Witness<'source> = (Anchor, EpochIndex, Fp, TachygramSetCommit);

    const INDEX: Index = Index::new(27);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, epoch, discriminant_entropy, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let discriminant = poseidon::qr_discriminant(discriminant_entropy);
        let anchor_last = anchor_prev
            .next_stamp(epoch, &stamp_commit)
            .map_err(|_e| ragu::Error::InvalidWitness("invalid anchor step".into()))?;
        Ok((
            (
                epoch,
                anchor_prev,
                anchor_last,
                QrDiscriminant::from(discriminant),
                QrProfile::ROOT,
                stamp_commit,
            ),
            (),
        ))
    }
}

/// Join two same-profile intakes whose spans meet.
///
/// Committed polynomials: both contents, the merged contents; three oracles.
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
    /// `(left_contents, right_contents, merged)`.
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(22);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_contents, right_contents, merged): Self::Witness<'source>,
        (epoch, anchor_prev, junction, discriminant, profile, left_commit): <Self::Left as Header>::Data,
        (
            right_epoch,
            right_anchor_prev,
            anchor_last,
            right_discriminant,
            right_profile,
            right_commit,
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(u64::from(epoch.0)) - Fp::from(u64::from(right_epoch.0)),
            "QrIntakeMerge: inputs cover different epochs",
        )?;
        enforce_zero(
            Fp::from(discriminant) - Fp::from(right_discriminant),
            "QrIntakeMerge: inputs derive from different discriminants",
        )?;
        enforce_zero(
            Fp::from(u64::from(profile.depth)) - Fp::from(u64::from(right_profile.depth)),
            "QrIntakeMerge: inputs sit at different depths",
        )?;
        enforce_zero(
            Fp::from(u64::from(profile.bits)) - Fp::from(u64::from(right_profile.bits)),
            "QrIntakeMerge: inputs sit at different profiles",
        )?;
        enforce_zero(
            Fp::from(junction) - Fp::from(right_anchor_prev),
            "QrIntakeMerge: right input does not continue the left span",
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
                epoch,
                anchor_prev,
                anchor_last,
                discriminant,
                profile,
                merged.commit(),
            ),
            (),
        ))
    }
}

/// Partition an intake's members at its own discriminant.
///
/// Committed polynomials: contents, both sides; three oracles.
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
    /// `(contents, residue, non_residue)`.
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(23);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (contents, residue, non_residue): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, profile, contents_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(contents.commit()),
            Eq::from(contents_commit),
            "QrIntakeSplit: contents do not match header",
        )?;
        enforce_poly_product(
            ctx,
            residue.as_ref(),
            non_residue.as_ref(),
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
                anchor_last,
                discriminant,
                profile,
                residue.commit(),
                non_residue.commit(),
            ),
            (),
        ))
    }
}

/// Extract one side of a partition and carry it down one level, attesting
/// the other side's class.
///
/// With $s$ the sibling, $g$ its interpolant and $h$ the quotient,
///
/// $$
///   g(X)^2 - c\,(X + R) = s(X)\, h(X)
/// $$
///
/// at the sibling's class $c$ holds only if every root of $s$ takes that
/// side at $R$, since each root leaves $g(x)^2 = c\,(x + R)$. With the
/// split's product, every member of the extracted class is then in the
/// child.
///
/// Committed polynomials: the sibling, its interpolant, its quotient; three
/// oracles. Gate cost is one scalar multiplication binding $R_1$ into the
/// challenge.
///
/// # Soundness
///
/// The child needs completeness, not purity: a consumer opens it nonzero at
/// a value of the child's own profile, and a stray member of the other class
/// only tightens that opening. The sibling is pinned to the header by
/// commit-equality and the challenge absorbs all three commitments and $R_1$
/// as $G_0 \cdot R_1$: the entropy is otherwise free, and a challenge that did
/// not depend on it would let the prover solve for the $R$ satisfying the
/// identity at $z$. The child's commitment is read off the header. Both header
/// commitments are selected by point arithmetic on `bit`, and the class
/// multiplier is linear in `bit`, so no constraint branches on the witness. The
/// parent's depth is checked below [`QrProfile::MAX_DEPTH`], so `bits` stays
/// below $2^{32} < p$ and distinct paths of one depth never share a profile.
#[derive(Debug)]
pub struct QrSideDescend;

impl Step for QrSideDescend {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrIntake;
    type Right = ();
    /// `(bit, sibling_contents, interpolant, quotient)`.
    type Witness<'source> = (bool, TachygramSetPoly, QrInterpolantPoly, QrQuotientPoly);

    const INDEX: Index = Index::new(24);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (bit, sibling_contents, interpolant, quotient): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, profile, residue, non_residue): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // TODO: a real circuit needs a bit decomposition of `depth` here; mock
        // ragu accepts the native comparison.
        if profile.depth >= u32::BITS {
            return Err(ragu::Error::InvalidWitness(
                "QrSideDescend: profile has no bit left for another side".into(),
            ));
        }

        let discriminant_commit = {
            #[expect(clippy::expect_used, reason = "constant size")]
            let &g0 = Pasta::host_generators(Pasta::baked())
                .g()
                .first()
                .expect("at least one generator");
            g0 * discriminant.0
        };

        // TODO: a real circuit must constrain `bit` boolean; the type carries it
        // under mock ragu.
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
            discriminant_commit,
            sibling_commit.into(),
            interpolant_commit.into(),
            quotient_commit.into(),
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
                anchor_last,
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
/// `anchor_prev` is the epoch's opening boundary anchor and `anchor_last` its
/// terminal anchor. The bucket spans `[anchor_prev, anchor_last]`, so it
/// never leaves its epoch.
#[derive(Clone, Debug)]
pub struct QrBucket;

impl Header for QrBucket {
    /// `(epoch, anchor_prev, anchor_last, discriminant, profile, contents)`.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(18);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, discriminant, profile, contents) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
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

/// Seal a routed [`QrIntake`] into a [`QrBucket`], by pinning the span's
/// opening to an epoch boundary:
///
/// $$
///   \mathsf{anchor\_prev} = H_\mathsf{ep}(\mathsf{prev\_last},
///   \mathsf{epoch}).
/// $$
///
/// Committed polynomials: none.
///
/// # Soundness
///
/// Only an epoch transition produces an anchor in the epoch domain, so an
/// `anchor_prev` of this form is an epoch's opening boundary anchor.
/// `prev_last` is free, as at every seed; the lineage that consumes the
/// segment binds it. Epoch zero's opening anchor, [`Anchor::default`], is this
/// rule at $\mathsf{prev\_last} = 0$.
///
/// That `anchor_last` is the epoch's terminal anchor is a claim about what
/// was published, and closes through the consuming lineage: the crossing
/// after the segment folds `anchor_last` to a boundary anchor that the next
/// segment must open on, and that chain reaches the spend anchor consensus
/// checks. A bucket sealed short of the epoch ticks to an anchor nobody
/// published.
#[derive(Debug)]
pub struct QrBucketSeal;

impl Step for QrBucketSeal {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrBucket;
    type Right = ();
    /// `(prev_last)`, the terminal anchor of the preceding epoch.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(26);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (prev_last,): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, profile, contents): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(anchor_prev)
                - poseidon::anchor_next_epoch(Fp::from(prev_last), Fp::from(u64::from(epoch.0))),
            "QrBucketSeal: intake does not begin at the epoch boundary",
        )?;

        Ok((
            (
                epoch,
                anchor_prev,
                anchor_last,
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
/// bucket at the value for nonzero. With $x$ the value, $s_j = x + R_j$ and
/// $R_j = R_1 + (j - 1)$, each position witnesses a side $b_j$ and a root
/// $r_j$ with
///
/// $$
///   r_j^2 = \bigl(c - (c - 1)\,b_j\bigr)\, s_j,
///   \qquad
///   b_j = 0 \implies s_j \neq 0.
/// $$
///
/// A mask $m_j$ selects the bucket's path through two sums and a fold,
///
/// $$
///   \sum_j m_j = \mathsf{depth},
///   \qquad
///   \sum_j j\, m_j = \frac{\mathsf{depth}\,(\mathsf{depth} - 1)}{2},
///   \qquad
///   a_j = a_{j-1} + m_j\,(a_{j-1} + b_j),
/// $$
///
/// with positions indexed from zero and $a_0 = 0$; the fold ends at
/// $\mathsf{bits}$ exactly when the bucket's sides are the value's. The
/// emitted segment reads the value as a nullifier and covers the bucket's
/// own span, one epoch, so consecutive epochs' segments need an
/// [`EndEpochUnspentSeed`](super::pool::EndEpochUnspentSeed) between them.
///
/// Committed polynomials: the sequence, the contents; two oracles. Gate cost
/// is one scalar multiplication binding the value into the challenge and
/// about seven multiplications per position.
///
/// # Soundness
///
/// $c$ is a non-residue, so when $s_j \neq 0$ exactly one of $s_j$, $c\,s_j$
/// is a square and $b_j$ is the value's true side there; when $s_j = 0$
/// both sides have root zero and the nonzero rule forces the residue side,
/// where [`QrIntakeSplit`] files the exceptional value. Every side is
/// therefore the value's own, independent of the header, and the masked fold
/// compares the bucket's prefix against them. Among boolean vectors of weight
/// `depth` the index sum is minimised exactly by the leading positions, so
/// the two sums force the mask to be that prefix and bound `depth` by
/// [`QrProfile::MAX_DEPTH`] in circuit. Positions past `depth` are tested but
/// compared to nothing. $R_1$ is the bucket's own
/// `discriminant`, the one its routing classified at. `value` is absorbed as
/// $G_0 \cdot \mathsf{value}$ into the sequence challenge, so the sequence
/// names the emitted member.
#[derive(Debug)]
pub struct QrUnspentInit;

impl Step for QrUnspentInit {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(value, classes, mask, sequence, contents)`.
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(25);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (value, classes, mask, sequence, contents): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, profile, contents_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(contents.commit()),
            Eq::from(contents_commit),
            "QrUnspentInit: contents do not match the bucket",
        )?;
        enforce_nonzero(Fp::from(value), "QrUnspentInit: tested value is zero")?;

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

        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let sequence_commit = sequence.commit();
        let z = ctx.derive_challenge(&[sequence_commit.into(), g0 * Fp::from(value)])?;
        let sequence_at_z = sequence.eval(z);
        let member_at_z = indexed_multiset::direct_eval([(u64::from(epoch), value.into())], z);
        enforce_zero(
            sequence_at_z - member_at_z,
            "QrUnspentInit: sequence does not match the tested value",
        )?;
        ctx.enforce_poly_query(sequence_commit.into(), z, sequence_at_z)?;

        let contents_at_value = contents.eval(value.into());
        ctx.enforce_poly_query(contents_commit.into(), value.into(), contents_at_value)?;
        enforce_nonzero(
            contents_at_value,
            "QrUnspentInit: found nullifier in the bucket",
        )?;

        let nf = Nullifier::from(value);
        Ok((
            (
                anchor_prev,
                (epoch, nf),
                sequence_commit,
                (epoch, nf),
                anchor_last,
            ),
            (),
        ))
    }
}
