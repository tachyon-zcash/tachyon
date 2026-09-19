//! QR epoch evidence: one epoch's tachygrams partitioned by profile.
//!
//! Each depth classifies at a discriminant of the progression
//!
//! $$
//!   R_{j+1} = R_1 + j,
//! $$
//!
//! whose base $R_1$ the builder samples privately, so a network can be routed
//! while its epoch is still in flight. Every header carries $R_1$, so depth
//! $j$ classifies at $R_{j+1}$, and a value takes the residue side there iff
//! $x + R_{j+1}$ is a square or zero.
//!
//! [`QrSummaryIntakeInit`] starts a [`QrIntake`] from a [`Summary`], and
//! [`QrStampIntakeSeed`] from one unsummarized stamp. [`QrIntakeSplit`]
//! partitions an intake at its discriminant into [`QrIntakeSides`],
//! [`QrSideDescend`] carries one side down a level, and [`QrIntakeMerge`]
//! joins two same-profile intakes whose spans meet. [`QrBucketSeal`] admits a
//! routed intake as a [`QrBucket`], and [`QrUnspentInit`] tests a value's
//! profile against a bucket and opens the bucket at it.
//!
//! A builder that keeps a network's buckets folds them into one
//! [`QrBucketTree`] and retains a single proof for its root:
//! [`QrBucketTreeInit`] admits one bucket, [`QrBucketTreeFuse`] joins two
//! trees of one network, [`QrBucketTreeDescend`] walks a path down to a
//! subtree, and [`QrBucketTreeOpen`] replays the bucket a leaf holds.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use group::Curve as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use super::{pool::ArbitraryUnspent, summary::Summary};
pub use crate::collections::qr::classify;
use crate::{
    collections::{indexed_multiset, qr::QUADRATIC_NON_RESIDUE},
    digest::poseidon,
    nullifier::Nullifier,
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrInterpolantPoly, QrProfile,
        QrQuotientPoly, QrTreeFork, QrTreeRoot, Tachygram, TachygramSetCommit, TachygramSetPoly,
    },
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::enforce_poly_product,
};

/// Tachygrams under routing. Every member of `contents` takes `profile`, and
/// a split classifies at `discriminant.at(profile.depth)`.
#[derive(Clone, Debug)]
pub struct QrIntake;

impl Header for QrIntake {
    /// `(epoch, anchor_prev, anchor_last, discriminant, profile, contents)`.
    /// The contents were drawn from the folds the coverage extent
    /// `(anchor_prev, anchor_last]` certifies; `discriminant` is the network's
    /// $R_1$, prover-chosen and threaded unchanged.
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
        let (epoch, anchor_prev, anchor_last, discriminant, profile, contents) = *data;
        (
            vec![
                Fp::from(epoch),
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
    /// `(epoch, anchor_prev, anchor_last, discriminant, profile, non_residue,
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

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, discriminant, profile, non_residue, residue) = *data;
        (
            vec![
                Fp::from(epoch),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
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
/// `discriminant` is free here, as every seed witness is, and stays free: it
/// is the builder's own routing base. [`QrIntakeMerge`] requires the two
/// halves to agree on it, so one network classifies at one progression.
#[derive(Debug)]
pub struct QrSummaryIntakeInit;

impl Step for QrSummaryIntakeInit {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = QrIntake;
    type Right = ();
    /// `(discriminant)`.
    type Witness<'source> = (QrDiscriminant,);

    const INDEX: Index = Index::new(20);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (discriminant,): Self::Witness<'source>,
        (summary_epoch, summary_anchor_prev, summary_anchor_last, summary_acc_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((
            (
                summary_epoch,
                summary_anchor_prev,
                summary_anchor_last,
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
/// `discriminant` is free, as at [`QrSummaryIntakeInit`]. `stamp_commit` is
/// folded into `anchor_last`.
#[derive(Debug)]
pub struct QrStampIntakeSeed;

impl Step for QrStampIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    /// `(anchor_prev, epoch, discriminant, stamp_commit)`.
    type Witness<'source> = (Anchor, EpochIndex, QrDiscriminant, TachygramSetCommit);

    const INDEX: Index = Index::new(26);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, epoch, discriminant, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let anchor_last = anchor_prev
            .next_stamp(epoch, &stamp_commit)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
        Ok((
            (
                epoch,
                anchor_prev,
                anchor_last,
                discriminant,
                QrProfile::ROOT,
                stamp_commit,
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
    /// `(left_contents, right_contents, merged)`.
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(21);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_contents, right_contents, merged): Self::Witness<'source>,
        (
            left_epoch,
            left_anchor_prev,
            left_anchor_last,
            left_discriminant,
            left_profile,
            left_commit,
        ): <Self::Left as Header>::Data,
        (
            right_epoch,
            right_anchor_prev,
            right_anchor_last,
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
            Fp::from(left_anchor_last) - Fp::from(right_anchor_prev),
            "QrIntakeMerge: left.anchor_last must equal right.anchor_prev",
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
                right_anchor_last,
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
    /// `(contents, non_residue, residue)`.
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(22);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (contents, non_residue, residue): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, profile, contents_commit): <Self::Left as Header>::Data,
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
                anchor_last,
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
/// sibling, interpolant and quotient commitments. Every root of the sibling
/// then satisfies $u(x)^2 = c \cdot (x + R)$ at the sibling's class $c$, and
/// the split's product places every member of the other class in the child. The
/// child may hold a stray member of the sibling's class; consumers open it
/// nonzero, so a stray member cannot pass a value that is present. $R$ is read
/// off the header, so a descent classifies at the same base as every other
/// step of the network. The parent's depth is
/// checked below [`QrProfile::MAX_DEPTH`], so `bits` stays below $2^{32}$ and
/// one depth's paths have distinct profiles.
#[derive(Debug)]
pub struct QrSideDescend;

impl Step for QrSideDescend {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrIntake;
    type Right = ();
    /// `(bit, sibling_contents, interpolant, quotient)`.
    type Witness<'source> = (bool, TachygramSetPoly, QrInterpolantPoly, QrQuotientPoly);

    const INDEX: Index = Index::new(23);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (bit, sibling_contents, interpolant, quotient): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, profile, non_residue, residue): <Self::Left as Header>::Data,
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
/// `anchor_prev` has epoch-link form absorbing `epoch`, which
/// [`QrBucketSeal`] checks. `anchor_last` is the output of the bucket's last
/// fold; whether it is the epoch's terminal anchor is not checked here. The
/// bucket covers `(anchor_prev, anchor_last]`, so it never leaves its epoch.
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

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, discriminant, profile, contents) = *data;
        (
            vec![
                Fp::from(epoch),
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

/// Seal a routed [`QrIntake`] into a [`QrBucket`], by pinning the extent's
/// `anchor_prev` to epoch-link form: it is the epoch link of
/// `anchor_prev_prev` into `epoch`.
///
/// # Soundness
///
/// Only an epoch link produces an anchor in the epoch domain, so an
/// `anchor_prev` of this form absorbs `epoch`. That it is the *entry anchor*
/// of `epoch`, the first anchor of `epoch` in the accepted chain, is a claim
/// about what was published and not one this step makes:
/// `anchor_prev_prev` is free, as at every seed, and the lineage that consumes
/// the segment binds it. Epoch zero's entry anchor, [`Anchor::default`], is
/// this rule at an `anchor_prev_prev` of zero.
///
/// `discriminant` is not checked here. It is a prover-chosen routing base,
/// threaded unchanged from the root intake and required equal across
/// [`QrIntakeMerge`], so every split in the intake's history classified at
/// $R_1 + \mathsf{depth}$ under the same $R_1$ the bucket carries, which is
/// the progression [`QrUnspentInit`] walks. $R_1$ moves how members
/// distribute across buckets, never which bucket holds a given value under
/// that $R_1$, so a biased or prematurely revealed choice is one prover's
/// network and a wallet uses any valid one.
///
/// That `anchor_last` is the epoch's *terminal anchor*, its last anchor, is
/// likewise a claim about what was published, and this step does not check
/// it; [`QrUnspentInit`]'s crossing forces it through the lineage.
#[derive(Debug)]
pub struct QrBucketSeal;

impl Step for QrBucketSeal {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrBucket;
    type Right = ();
    /// `(anchor_prev_prev)`, the fold input of `anchor_prev`. Zero at genesis.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(25);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev_prev,): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, profile, contents): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(anchor_prev)
                - poseidon::anchor_next_epoch(Fp::from(anchor_prev_prev), Fp::from(epoch)),
            "QrBucketSeal: intake's first anchor is not an epoch link into its epoch",
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
/// bucket at the value for nonzero. The `MAX_DEPTH` positions
/// $j = 0, 1, \dots$ index the progression, so position $j$
/// classifies at $R_{j+1} = R_1 + j$. With $x$ the value and $s_j = x +
/// R_1 + j$, each position witnesses a side $b_j$ and a root $r_j$ with
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
/// The emitted segment reads the value as a nullifier and crosses the epoch
/// boundary: it witnesses the next epoch's nullifier as well, folds the
/// crossing from the bucket's `anchor_last`, and covers `[epoch, epoch + 1]`
/// in epoch space and `(anchor_prev, H_epoch(anchor_last, epoch + 1)]` in
/// anchor space. Consecutive epochs' segments therefore meet at the entry
/// anchor and fuse directly.
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
/// sides. Positions past `depth` are tested but compared to nothing. $R_1$ is
/// the bucket's own `discriminant`, the base its routing classified at, so
/// the exclusion holds for the network the bucket belongs to whatever base
/// that network chose. `value` and
/// `nf_next` are free, the profile fold fixing the first and the sequence
/// identity both;
/// [`UnspentBind`](super::pool::UnspentBind) forces each against the note's
/// genuine derivation.
///
/// The crossing is what makes the bucket's whole-epoch claim true. The
/// accepted chain holds exactly one anchor of epoch-link form absorbing
/// `epoch + 1`, the entry anchor of that epoch, folded from
/// `terminal(epoch)`. This step emits `H_epoch(a, epoch + 1)` for the
/// bucket's own `a`, so if `a` is not `terminal(epoch)` the result is on no
/// chain, and by preimage resistance neither is any fold downstream of it.
/// A bucket sealed short of the epoch therefore yields evidence no lineage
/// can carry to a consensus-checked spend. [`QrBucketSeal`] still proves form
/// alone; whole-epoch coverage is established here and preserved by every
/// fuse and lift.
#[derive(Debug)]
pub struct QrUnspentInit;

impl Step for QrUnspentInit {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(value, nf_next, classes, mask, sequence, contents)`.
    type Witness<'source> = (
        Tachygram,
        Nullifier,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(24);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (value, nf_next, classes, mask, sequence, contents): Self::Witness<'source>,
        (
            bucket_epoch,
            bucket_anchor_prev,
            bucket_anchor_last,
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

        // The crossing out of the bucket's epoch, folded here rather than read
        // off `discriminant`, which is prover-chosen.
        let epoch_next = bucket_epoch.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness("QrUnspentInit: crossing past the final epoch".into())
        })?;
        let anchor_last = bucket_anchor_last
            .next_epoch(epoch_next)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

        let sequence_commit = sequence.commit();
        let z = ctx.derive_challenge(&[sequence_commit.into()])?;
        let sequence_at_z = sequence.eval(z);
        ctx.enforce_poly_query(sequence_commit.into(), z, sequence_at_z)?;

        let epoch_idx = u64::from(bucket_epoch);
        let crossing_at_z = indexed_multiset::direct_eval(
            [
                (epoch_idx, value.into()),
                (epoch_idx + 1, Fp::from(nf_next)),
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
                anchor_last,
            ),
            (),
        ))
    }
}

/// A Poseidon Merkle root over one network's sealed buckets.
///
/// Every leaf under `root` is the [`poseidon::qr_bucket_digest`] of a bucket
/// whose own `(epoch, anchor_prev, anchor_last, discriminant)` are the four
/// this header carries. A one-leaf tree's root is that leaf's digest.
///
/// The tree claims nothing about which buckets it holds. A tree over one
/// bucket is as valid as a tree over a whole network, and a builder that omits
/// a bucket can only fail to answer for it. A bucket's own exclusion claim is
/// whole-epoch without the tree, so completeness has nothing to add.
#[derive(Clone, Debug)]
pub struct QrBucketTree;

impl Header for QrBucketTree {
    /// `(epoch, anchor_prev, anchor_last, discriminant, root)`.
    type Data = (EpochIndex, Anchor, Anchor, QrDiscriminant, QrTreeRoot);

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, discriminant, root) = *data;
        (
            vec![
                Fp::from(epoch),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
                Fp::from(discriminant),
                Fp::from(root),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Admit one sealed [`QrBucket`] as a one-leaf [`QrBucketTree`].
///
/// # Soundness
///
/// Every field is threaded from a bucket PCD, and the leaf digest is derived
/// from three of them, so the emitted root is the digest of a bucket
/// [`QrBucketSeal`] produced and the four network fields are that bucket's.
#[derive(Debug)]
pub struct QrBucketTreeInit;

impl Step for QrBucketTreeInit {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = QrBucketTree;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(28);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, profile, contents): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let root = QrTreeRoot(poseidon::qr_bucket_digest(
            Fp::from(u64::from(profile.depth)),
            Fp::from(u64::from(profile.bits)),
            Eq::from(contents).to_affine(),
        ));

        Ok(((epoch, anchor_prev, anchor_last, discriminant, root), ()))
    }
}

/// Join two [`QrBucketTree`]s of one network under a fresh node.
///
/// # Soundness
///
/// Both roots are threaded, and the four equalities make the emitted header's
/// network fields true of every leaf beneath either input. The fields are
/// *equal*, not chained as [`QrIntakeMerge`] chains a span: a consumer reads
/// the extent off the tree, so a tree spanning more than its leaves do would
/// let a bucket's exclusion cover folds the bucket never held. Every bucket of
/// one network shares all four, so equality costs a builder nothing.
#[derive(Debug)]
pub struct QrBucketTreeFuse;

impl Step for QrBucketTreeFuse {
    type Aux<'source> = ();
    type Left = QrBucketTree;
    type Output = QrBucketTree;
    type Right = QrBucketTree;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(29);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (left_epoch, left_anchor_prev, left_anchor_last, left_discriminant, left_root): <Self::Left as Header>::Data,
        (right_epoch, right_anchor_prev, right_anchor_last, right_discriminant, right_root): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_epoch) - Fp::from(right_epoch),
            "QrBucketTreeFuse: inputs cover different epochs",
        )?;
        enforce_zero(
            Fp::from(left_anchor_prev) - Fp::from(right_anchor_prev),
            "QrBucketTreeFuse: inputs open at different anchors",
        )?;
        enforce_zero(
            Fp::from(left_anchor_last) - Fp::from(right_anchor_last),
            "QrBucketTreeFuse: inputs close at different anchors",
        )?;
        enforce_zero(
            Fp::from(left_discriminant) - Fp::from(right_discriminant),
            "QrBucketTreeFuse: inputs derive from different discriminants",
        )?;

        let root = QrTreeRoot(poseidon::qr_tree_node(
            Fp::from(left_root),
            Fp::from(right_root),
        ));

        Ok((
            (
                left_epoch,
                left_anchor_prev,
                left_anchor_last,
                left_discriminant,
                root,
            ),
            (),
        ))
    }
}

/// Walk [`QrTreeFork::LEVELS`] levels of a Merkle path, emitting the subtree
/// the path reaches.
///
/// A path of `depth` levels takes `⌈depth / LEVELS⌉` of these in a chain, so
/// the depth a builder serves is its own choice and never a loop bound here.
/// Padding a tree to a multiple of `LEVELS` by fusing a subtree with itself
/// leaves duplicate leaves, which are harmless.
///
/// # Soundness
///
/// `node` starts threaded, each level's children are pinned to it by the node
/// hash, and the emitted root is one of the two children of a node reached
/// that way. Every leaf beneath a subtree of a valid tree is a leaf of that
/// tree, so the claim survives the descent. The domains separate leaf digests
/// from node values, so a path cannot stop one level short and present a node
/// as a bucket.
#[derive(Debug)]
pub struct QrBucketTreeDescend;

impl Step for QrBucketTreeDescend {
    type Aux<'source> = ();
    type Left = QrBucketTree;
    type Output = QrBucketTree;
    type Right = ();
    /// `(path)`, outermost level first.
    type Witness<'source> = ([QrTreeFork; QrTreeFork::LEVELS],);

    const INDEX: Index = Index::new(30);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (path,): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, root): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // TODO: a real circuit must constrain each fork's side boolean and
        // select between the children in-circuit; the type carries the first
        // and the native branch the second under mock ragu.
        let mut node = root;
        for fork in path {
            let QrTreeFork(_side, left_child, right_child) = fork;
            enforce_zero(
                Fp::from(node)
                    - poseidon::qr_tree_node(Fp::from(left_child), Fp::from(right_child)),
                "QrBucketTreeDescend: children do not hash to the node",
            )?;
            node = fork.descend();
        }

        Ok(((epoch, anchor_prev, anchor_last, discriminant, node), ()))
    }
}

/// Replay the [`QrBucket`] a one-leaf [`QrBucketTree`] holds.
///
/// # Soundness
///
/// The witnessed profile and contents commitment are pinned jointly to `root`
/// by the leaf digest, and `root` is a leaf digest by the lineage: a
/// [`QrBucketTreeInit`] derived it from a bucket header, and neither the fuse
/// nor the descent reads it. Preimage resistance then makes the emitted header
/// one [`QrBucketSeal`] emitted, so this second producer of [`QrBucket`]
/// establishes nothing the seal did not.
///
/// Binding the profile is what stops the interesting forgery: a real bucket's
/// contents presented under the tested value's own profile would pass
/// [`QrUnspentInit`]'s fold and open nonzero, proving exclusion for a value
/// published in a different bucket.
#[derive(Debug)]
pub struct QrBucketTreeOpen;

impl Step for QrBucketTreeOpen {
    type Aux<'source> = ();
    type Left = QrBucketTree;
    type Output = QrBucket;
    type Right = ();
    /// `(profile, contents)`, the leaf's preimage.
    type Witness<'source> = (QrProfile, TachygramSetCommit);

    const INDEX: Index = Index::new(31);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (profile, contents): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, discriminant, root): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(root)
                - poseidon::qr_bucket_digest(
                    Fp::from(u64::from(profile.depth)),
                    Fp::from(u64::from(profile.bits)),
                    Eq::from(contents).to_affine(),
                ),
            "QrBucketTreeOpen: witnessed bucket is not the tree's leaf",
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
