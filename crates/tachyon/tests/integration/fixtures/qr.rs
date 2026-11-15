extern crate alloc;

use alloc::{vec, vec::Vec};
use core::iter;

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta::Pasta;
use rand_core::CryptoRng;
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};
use zcash_tachyon::{
    Anchor, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, Tachygram, TachygramSetPoly,
    constants::EVIDENCE_TREE_ARITY,
    nullifier::Nullifier,
    pasta::{EpAffine, Eq, Fp},
    stamp::proof::{App, evidence, pool, qr},
    witness,
};

use super::{Proved, keyed_rng, pool::PoolSim, wallet::shared_sk};

/// The root, one level down, the last level with a bit to spare, and a full
/// register.
pub(crate) const QR_DEPTHS: [u32; 4] = [0, 1, 31, u32::BITS];

pub(crate) fn qr_twins() -> [Fp; 2] {
    let discriminant = shared_discriminant();
    // An element `n - discriminant` takes the quadratic character of `n + level`
    // at each level, and the 32 consecutive characters from 40621 match those
    // from 126676, so the member shares the absent value's whole profile.
    let absent = Fp::from(40_621u64) - Fp::from(discriminant);
    let member = Fp::from(126_676u64) - Fp::from(discriminant);
    assert_ne!(absent, member);
    assert_eq!(
        qr_profile_of(absent, discriminant, u32::BITS),
        qr_profile_of(member, discriminant, u32::BITS)
    );
    [absent, member]
}

/// The first keyed shared discriminant whose depth-two profiles differ for the
/// shared 500-value note's commitment and epoch-zero nullifier under the shared
/// key.
pub(crate) fn shared_discriminant() -> QrDiscriminant {
    let note = PoolSim::shared_note(500);
    let nf = shared_sk()
        .derive_proof_private()
        .nk
        .derive_note_private(note.psi)
        .derive_nullifier(EpochIndex::new(0));
    let mut rng = keyed_rng("shared discriminant", &[]);
    iter::repeat_with(|| QrDiscriminant::random(&mut rng))
        .find(|&discriminant| {
            qr_profile_of(Fp::from(note.commitment()), discriminant, 2)
                != qr_profile_of(Fp::from(nf), discriminant, 2)
        })
        .unwrap()
}

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

    /// Reads a seal kept for the process.
    pub fn sealed(&self, app: &App<'_>, anchor_final_prev: Anchor) -> QrBucketEntry {
        static SEALED: Proved<QrBucketEntry> = Proved::new("qr_sealed");

        let (epoch, start, end, discriminant, profile) = *self.pcd.data();
        let mut key = u32::from(epoch).to_le_bytes().to_vec();
        for value in [Fp::from(start), Fp::from(end), Fp::from(discriminant)] {
            key.extend_from_slice(&value.to_bytes());
        }
        key.extend_from_slice(&profile.depth.to_le_bytes());
        key.extend_from_slice(&profile.bits.to_le_bytes());
        key.extend_from_slice(&Eq::from(self.pcd.commitments()[0]).to_affine().to_bytes());
        key.extend_from_slice(&Fp::from(anchor_final_prev).to_bytes());
        SEALED.get(&key, |rng| self.clone().seal(rng, app, anchor_final_prev))
    }

    /// Proves a seal with the caller's rng.
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

    pub(crate) fn split<RNG: CryptoRng, const N: usize>(
        self,
        rng: &mut RNG,
        app: &App<'_>,
        kept: [bool; N],
    ) -> [Self; N] {
        let (_epoch, _anchor_prev, _anchor_end, discriminant, profile) = *self.pcd.data();
        let (residue, non_residue) =
            self.members.iter().copied().partition(|&member| {
                qr::classify(Fp::from(member), discriminant.at(profile.depth)).0
            });
        self.split_with_factors(
            rng,
            app,
            kept,
            &[(non_residue, Fp::ONE), (residue, Fp::ONE)],
        )
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
    pub index: usize,
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
    pub(crate) fn of(app: &App<'_>, buckets: &[QrBucketEntry]) -> Self {
        static LEAF_PAIRS: Proved<ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTreePair>> =
            Proved::new("evidence_leaf_pair");
        static PAIR_FUSES: Proved<ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTreePair>> =
            Proved::new("evidence_pair_fuse");
        static TREES: Proved<ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>> =
            Proved::new("evidence_tree_fuse");
        static CAPS: Proved<ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>> =
            Proved::new("evidence_cap");

        fn node_key(buckets: &[&QrBucketEntry]) -> Vec<u8> {
            let mut key = u32::try_from(buckets.len()).unwrap().to_le_bytes().to_vec();
            for bucket in buckets {
                let (epoch, start, next, discriminant, profile, bridge) = *bucket.pcd.data();
                key.extend_from_slice(&u32::from(epoch).to_le_bytes());
                for value in [Fp::from(start), Fp::from(next), Fp::from(discriminant)] {
                    key.extend_from_slice(&value.to_bytes());
                }
                key.extend_from_slice(&profile.depth.to_le_bytes());
                key.extend_from_slice(&profile.bits.to_le_bytes());
                key.extend_from_slice(&EpAffine::from(bridge).to_bytes());
            }
            key
        }

        fn leaf_pair(
            app: &App<'_>,
            buckets: &[&QrBucketEntry],
        ) -> ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTreePair> {
            let [first, second] = <[_; 2]>::try_from(buckets).unwrap();
            LEAF_PAIRS.get(&node_key(buckets), |rng| {
                let (pcd, ()) = app
                    .fuse(
                        rng,
                        evidence::EvidenceTreeLeafPair,
                        (),
                        first.pcd.clone(),
                        second.pcd.clone(),
                    )
                    .unwrap();
                pcd
            })
        }

        fn pair_fuse(
            app: &App<'_>,
            buckets: &[&QrBucketEntry],
            left: ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>,
            right: ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>,
        ) -> ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTreePair> {
            PAIR_FUSES.get(&node_key(buckets), |rng| {
                let (pcd, ()) = app
                    .fuse(rng, evidence::EvidenceTreePairFuse, (), left, right)
                    .unwrap();
                pcd
            })
        }

        fn node(app: &App<'_>, buckets: &[&QrBucketEntry]) -> EvidenceTreeEntry {
            let (left, right, leaves) = if buckets.len() == EVIDENCE_TREE_ARITY {
                let left = leaf_pair(app, &buckets[..2]);
                let right = leaf_pair(app, &buckets[2..]);
                let roots = [left.data().4, left.data().5, right.data().4, right.data().5];
                let leaves = buckets
                    .iter()
                    .enumerate()
                    .map(|(index, bucket)| EvidenceLeaf {
                        index,
                        profile: bucket.pcd.data().4,
                        contents: scaled_qr_contents(&bucket.members, Fp::ONE),
                        members: bucket.members.clone(),
                        path: vec![([index & 2 != 0, index & 1 != 0], roots)],
                    })
                    .collect::<Vec<_>>();
                (left, right, leaves)
            } else {
                let child_width = buckets.len() / EVIDENCE_TREE_ARITY;
                let children = buckets
                    .chunks(child_width)
                    .map(|part| node(app, part))
                    .collect::<Vec<_>>();
                let roots = [
                    children[0].pcd.data().4,
                    children[1].pcd.data().4,
                    children[2].pcd.data().4,
                    children[3].pcd.data().4,
                ];
                let half = buckets.len() / 2;
                let left = pair_fuse(
                    app,
                    &buckets[..half],
                    children[0].pcd.clone(),
                    children[1].pcd.clone(),
                );
                let right = pair_fuse(
                    app,
                    &buckets[half..],
                    children[2].pcd.clone(),
                    children[3].pcd.clone(),
                );
                let leaves = children
                    .into_iter()
                    .enumerate()
                    .flat_map(|(digit, child)| {
                        child.leaves.into_iter().map(move |mut leaf| {
                            leaf.index += digit * child_width;
                            leaf.path
                                .insert(0, ([digit & 2 != 0, digit & 1 != 0], roots));
                            leaf
                        })
                    })
                    .collect::<Vec<_>>();
                (left, right, leaves)
            };
            let pcd = TREES.get(&node_key(buckets), |rng| {
                let (pcd, ()) = app
                    .fuse(rng, evidence::EvidenceTreeFuse, (), left, right)
                    .unwrap();
                pcd
            });
            EvidenceTreeEntry { pcd, leaves }
        }

        assert!(!buckets.is_empty());
        let mut width = EVIDENCE_TREE_ARITY;
        let mut depth = 1;
        while width < buckets.len() {
            width *= EVIDENCE_TREE_ARITY;
            depth += 1;
        }
        let mut padded = buckets.iter().collect::<Vec<_>>();
        padded.resize(width, buckets.last().unwrap());
        let mut tree = node(app, &padded);
        let mut cap_count = 0u32;
        while !(depth + usize::try_from(cap_count).unwrap())
            .is_multiple_of(evidence::EvidenceTreeDescend::LEVELS)
        {
            let mut key = node_key(&padded);
            key.extend_from_slice(&cap_count.to_le_bytes());
            let child = tree.pcd.data().4;
            tree.pcd = CAPS.get(&key, |rng| {
                let (pcd, ()) = app
                    .fuse(
                        rng,
                        evidence::EvidenceTreeCap,
                        (),
                        tree.pcd.clone(),
                        app.bootstrap_proof().clone().carry::<()>(()),
                    )
                    .unwrap();
                pcd
            });
            for leaf in &mut tree.leaves {
                leaf.path
                    .insert(0, ([false, false], [child; EVIDENCE_TREE_ARITY]));
            }
            cap_count += 1;
        }
        tree
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
                    index,
                    profile,
                    contents,
                    members,
                    path,
                }
            })
            .collect();

        Self { pcd: root, leaves }
    }

    pub(crate) fn descent(
        &self,
        app: &App<'_>,
        index: usize,
    ) -> ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree> {
        static DESCENTS: Proved<ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>> =
            Proved::new("evidence_descent");

        let mut key = Fp::from(self.pcd.data().4).to_bytes().to_vec();
        key.extend_from_slice(&u32::try_from(index).unwrap().to_le_bytes());
        DESCENTS.get(&key, |rng| {
            let mut node = self.pcd.clone();
            for chunk in self.leaves[index]
                .path
                .chunks(evidence::EvidenceTreeDescend::LEVELS)
            {
                let path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(chunk).unwrap();
                let witness = witness::evidence_tree_descend((*node.data(), ()), path);
                let (pcd, ()) = app
                    .fuse(
                        rng,
                        evidence::EvidenceTreeDescend,
                        witness,
                        node,
                        app.bootstrap_proof().clone().carry::<()>(()),
                    )
                    .unwrap();
                node = pcd;
            }
            node
        })
    }

    pub(crate) fn open<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        app: &App<'_>,
        leaf: &EvidenceLeaf,
    ) -> ragu_core::Result<QrBucketEntry> {
        let node = self.descent(app, leaf.index);

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
