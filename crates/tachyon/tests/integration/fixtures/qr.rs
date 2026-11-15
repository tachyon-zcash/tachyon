extern crate alloc;

use alloc::{vec, vec::Vec};

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta::Pasta;
use rand_core::CryptoRng;
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, Tachygram, TachygramSetPoly,
    constants::EVIDENCE_TREE_ARITY,
    nullifier::Nullifier,
    pasta::Fp,
    stamp::proof::{App, evidence, pool, qr},
    witness,
};

use super::Proved;

#[derive(Clone)]
pub(crate) struct QrIntakeEntry {
    pub pcd: ragu::Pcd<Pasta, ProductionRank, qr::QrIntake>,
    pub members: Vec<Tachygram>,
}

#[derive(Clone)]
pub(crate) struct QrBucketEntry {
    pub pcd: ragu::Pcd<Pasta, ProductionRank, qr::QrBucket>,
    pub members: Vec<Tachygram>,
}

impl QrIntakeEntry {
    pub(crate) fn empty(
        app: &App<'_>,
        anchor: Anchor,
        epoch: EpochIndex,
        discriminant: QrDiscriminant,
    ) -> Self {
        static EMPTY: Proved<QrIntakeEntry> = Proved::new("qr_empty_intake");

        let mut key = Fp::from(anchor).to_bytes().to_vec();
        key.extend_from_slice(&u32::from(epoch).to_le_bytes());
        key.extend_from_slice(&Fp::from(discriminant).to_bytes());
        EMPTY.get(&key, |rng| {
            let (pcd, ()) = app
                .seed(
                    rng,
                    qr::QrEmptyIntakeSeed,
                    witness::qr_empty_intake_seed(((), ()), anchor, epoch, discriminant),
                )
                .unwrap();
            Self {
                pcd,
                members: Vec::new(),
            }
        })
    }

    pub(crate) fn seal<RNG: CryptoRng>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        anchor_final_prev: Anchor,
    ) -> QrBucketEntry {
        let witness = witness::qr_bucket_seal((*self.pcd.data(), ()), anchor_final_prev);
        let (pcd, ()) = app
            .fuse(
                rng,
                qr::QrBucketSeal,
                witness,
                self.pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        QrBucketEntry {
            pcd,
            members: self.members,
        }
    }

    pub(crate) fn split<RNG: CryptoRng>(self, rng: &mut RNG, app: &App<'_>) -> (Self, Self) {
        let (_epoch, _anchor_prev, _anchor_end, discriminant, profile) = *self.pcd.data();
        let (residue, non_residue) =
            self.members.iter().copied().partition(|&member| {
                qr::classify(Fp::from(member), discriminant.at(profile.depth)).0
            });
        self.split_with_factors(
            rng,
            app,
            [false, true],
            &[(non_residue, Fp::ONE), (residue, Fp::ONE)],
        )
        .into()
    }

    /// Explicit factors in non-residue/residue order, including their scalar
    /// factors.
    pub(crate) fn split_with_factors<RNG: CryptoRng, const N: usize>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        kept: [bool; N],
        factors: &[(Vec<Tachygram>, Fp); 2],
    ) -> [Self; N] {
        let polynomials = factors
            .each_ref()
            .map(|factor| scaled_qr_contents(&factor.0, factor.1));
        let (sides, ()) = app
            .fuse(
                rng,
                qr::QrIntakeSplit,
                polynomials.into(),
                self.pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();

        kept.map(|side| {
            let sibling = &factors[usize::from(!side)];
            let (interpolant, quotient) =
                witness::qr_side_select((*sides.data(), ()), &sibling.0, side);
            let mut scaled_quotient: Polynomial<Fp, ProductionRank> = quotient.into();
            scaled_quotient.scale(sibling.1.invert().unwrap());
            let (selection, ()) = app
                .fuse(
                    rng,
                    qr::QrSideSelect,
                    (interpolant, scaled_quotient.into()),
                    sides.clone(),
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            let members = factors[usize::from(side)].0.clone();
            let (pcd, ()) = app
                .fuse(
                    rng,
                    qr::QrSideDescend,
                    witness::qr_side_descend((*sides.data(), *selection.data()), side),
                    sides.clone(),
                    selection,
                )
                .unwrap();
            Self { pcd, members }
        })
    }
}

pub(crate) fn scaled_qr_contents(members: &[Tachygram], scale: Fp) -> TachygramSetPoly {
    let monic: TachygramSetPoly = members.iter().copied().collect();
    let mut poly: Polynomial<Fp, ProductionRank> = monic.into();
    poly.scale(scale);
    TachygramSetPoly::arbitrary(poly)
}

#[derive(Clone)]
pub(crate) struct EvidenceLeaf {
    pub profile: QrProfile,
    pub contents: TachygramSetPoly,
    pub members: Vec<Tachygram>,
    pub path: Vec<([bool; 2], [EvidenceTreeRoot; EVIDENCE_TREE_ARITY])>,
}

pub(crate) struct EvidenceTreeEntry {
    pub pcd: ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>,
    pub leaves: Vec<EvidenceLeaf>,
}

impl EvidenceTreeEntry {
    pub(crate) fn build<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        buckets: Vec<QrBucketEntry>,
    ) -> Self {
        let scales = vec![Fp::ONE; buckets.len()];
        Self::build_with_scales(rng, app, buckets, scales)
    }

    pub(crate) fn build_with_scales<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        mut buckets: Vec<QrBucketEntry>,
        mut scales: Vec<Fp>,
    ) -> Self {
        assert!(!buckets.is_empty());
        assert_eq!(buckets.len(), scales.len());

        let mut width = EVIDENCE_TREE_ARITY;
        let mut depth = 1;
        while width < buckets.len() {
            width *= EVIDENCE_TREE_ARITY;
            depth += 1;
        }
        while buckets.len() < width {
            let last = buckets.last().unwrap();
            buckets.push(QrBucketEntry {
                pcd: last.pcd.clone(),
                members: last.members.clone(),
            });
            scales.push(*scales.last().unwrap());
        }

        let (proofs, held): (Vec<_>, Vec<_>) = buckets
            .into_iter()
            .zip(scales)
            .map(|(bucket, scale)| {
                let (_epoch, _anchor_start, _anchor_next, _discriminant, profile, _) =
                    *bucket.pcd.data();
                let contents = scaled_qr_contents(&bucket.members, scale);
                (bucket.pcd, (profile, contents, bucket.members))
            })
            .unzip();

        let mut pairs = Vec::with_capacity(width / 2);
        let mut admitted = proofs.into_iter();
        while let (Some(first), Some(second)) = (admitted.next(), admitted.next()) {
            let (pair, ()) = app
                .fuse(rng, evidence::EvidenceTreeLeafPair, (), first, second)
                .unwrap();
            pairs.push(pair);
        }

        let mut levels = vec![
            pairs
                .iter()
                .flat_map(|pair| [pair.data().4, pair.data().5])
                .collect::<Vec<_>>(),
        ];
        let mut layer = Vec::with_capacity(pairs.len() / 2);
        let mut halves = pairs.into_iter();
        while let (Some(left), Some(right)) = (halves.next(), halves.next()) {
            let (pcd, ()) = app
                .fuse(rng, evidence::EvidenceTreeFuse, (), left, right)
                .unwrap();
            layer.push(pcd);
        }
        levels.push(layer.iter().map(|pcd| pcd.data().4).collect());

        while layer.len() > 1 {
            let mut parents = Vec::with_capacity(layer.len() / EVIDENCE_TREE_ARITY);
            let mut children = layer.into_iter();
            while let (Some(first), Some(second), Some(third), Some(fourth)) = (
                children.next(),
                children.next(),
                children.next(),
                children.next(),
            ) {
                let (left, ()) = app
                    .fuse(rng, evidence::EvidenceTreePairFuse, (), first, second)
                    .unwrap();
                let (right, ()) = app
                    .fuse(rng, evidence::EvidenceTreePairFuse, (), third, fourth)
                    .unwrap();
                let (pcd, ()) = app
                    .fuse(rng, evidence::EvidenceTreeFuse, (), left, right)
                    .unwrap();
                parents.push(pcd);
            }
            levels.push(parents.iter().map(|pcd| pcd.data().4).collect());
            layer = parents;
        }

        let mut root = layer.pop().unwrap();
        let mut caps = Vec::new();
        while (depth + caps.len()) % evidence::EvidenceTreeDescend::LEVELS != 0 {
            caps.push(root.data().4);
            let (pcd, ()) = app
                .fuse(
                    rng,
                    evidence::EvidenceTreeCap,
                    (),
                    root,
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            root = pcd;
        }

        let leaves = held
            .into_iter()
            .enumerate()
            .map(|(index, (profile, contents, members))| {
                let mut path: Vec<_> = caps
                    .iter()
                    .rev()
                    .map(|child| ([false, false], [*child; EVIDENCE_TREE_ARITY]))
                    .collect();
                path.extend((0..depth).rev().map(|level| {
                    let base = EVIDENCE_TREE_ARITY * (index >> (2 * (level + 1)));
                    let digit = (index >> (2 * level)) & 3;
                    (
                        [digit & 2 != 0, digit & 1 != 0],
                        [
                            levels[level][base],
                            levels[level][base + 1],
                            levels[level][base + 2],
                            levels[level][base + 3],
                        ],
                    )
                }));
                EvidenceLeaf {
                    profile,
                    contents,
                    members,
                    path,
                }
            })
            .collect();

        Self { pcd: root, leaves }
    }

    pub(crate) fn open<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        leaf: &EvidenceLeaf,
    ) -> ragu_core::Result<QrBucketEntry> {
        let mut node = self.pcd.clone();
        for chunk in leaf.path.chunks(evidence::EvidenceTreeDescend::LEVELS) {
            let path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(chunk).map_err(
                |_error| ragu_core::Error::InvalidWitness("incomplete evidence path".into()),
            )?;
            let witness = witness::evidence_tree_descend((*node.data(), ()), path);
            let (pcd, ()) = app.fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness,
                node,
                app.bootstrap_proof().clone().carry::<()>(()),
            )?;
            node = pcd;
        }

        let witness =
            witness::evidence_tree_open((*node.data(), ()), leaf.profile, leaf.contents.clone());
        let (pcd, ()) = app.fuse(
            rng,
            evidence::EvidenceTreeOpen,
            witness,
            node,
            app.bootstrap_proof().clone().carry::<()>(()),
        )?;
        Ok(QrBucketEntry {
            pcd,
            members: leaf.members.clone(),
        })
    }
}

pub(crate) fn qr_profile_of(value: Fp, discriminant: QrDiscriminant, depth: u32) -> QrProfile {
    let mut profile = QrProfile::ROOT;
    for level in 0..depth {
        profile = profile.descend(qr::classify(value, discriminant.at(level)).0);
    }
    profile
}

impl QrBucketEntry {
    pub(crate) fn segment<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        nf: impl Fn(EpochIndex) -> Nullifier,
    ) -> ragu::Pcd<Pasta, ProductionRank, pool::ArbitraryUnspent> {
        let (epoch, ..) = *self.pcd.data();
        let witness = witness::qr_unspent_init((*self.pcd.data(), ()), nf(epoch).into());
        let (segment, ()) = app
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness,
                self.pcd.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        segment
    }
}
