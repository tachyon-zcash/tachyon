extern crate alloc;

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::iter;

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta::Pasta;
use rand_core::CryptoRng;
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};
use zcash_tachyon::{
    Anchor, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, Tachygram, TachygramSetBridge,
    TachygramSetPoly,
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

/// `[absent, exceptional, companion]`: three values that take the same side
/// at all 32 levels under the shared discriminant.
///
/// Under discriminant $R$ the class of $n - R$ at level $j$ is the quadratic
/// character of $n + j$, so a profile depends on $n$ alone. The exceptional
/// value is $n = -31$, whose shifted value is zero at level 31, where
/// selection files it on the residue side. The absent value and the
/// companion are the two smallest positive $n$ whose characters match those
/// of $-31, -30, \dots, -1$ at levels 0 to 30 and are a square's at level 31.
/// An exhaustive scan upward from 1, one Jacobi symbol per integer, found
/// them.
///
/// A change to `QrDiscriminant::at` or `qr::classify` would invalidate the
/// two constants, and the assertions here would fail.
pub(crate) fn qr_profile_triplet() -> [Fp; 3] {
    let discriminant = shared_discriminant();
    let absent = Fp::from(1_915_239_271u64) - Fp::from(discriminant);
    let exceptional = -Fp::from(discriminant) - Fp::from(31u64);
    let companion = Fp::from(5_828_521_534u64) - Fp::from(discriminant);
    assert_ne!(absent, exceptional);
    assert_ne!(absent, companion);
    assert_ne!(exceptional, companion);
    assert_eq!(
        qr_profile_of(absent, discriminant, u32::BITS),
        qr_profile_of(exceptional, discriminant, u32::BITS)
    );
    assert_eq!(
        qr_profile_of(absent, discriminant, u32::BITS),
        qr_profile_of(companion, discriminant, u32::BITS)
    );
    [absent, exceptional, companion]
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
    pub header: (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetBridge,
    ),
    pub contents: TachygramSetPoly,
    pub members: Vec<Tachygram>,
    pub path: Vec<([bool; 2], [EvidenceTreeRoot; EVIDENCE_TREE_ARITY])>,
}

impl EvidenceLeaf {
    pub(crate) fn profile(&self) -> QrProfile {
        let (_epoch, _anchor_start, _anchor_next, _discriminant, profile, _contents_hash) =
            self.header;
        profile
    }
}

#[derive(Clone)]
pub(crate) struct EvidenceTreeEntry {
    pub pcd: ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>,
    pub leaves: Vec<EvidenceLeaf>,
    pub real_leaves: usize,
}

impl EvidenceTreeEntry {
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

    pub(crate) fn build<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        buckets: &[QrBucketEntry],
    ) -> Self {
        fn leaf_pair<RNG: CryptoRng>(
            rng: &mut RNG,
            app: &App<'_>,
            buckets: &[&QrBucketEntry],
            pairs: &mut BTreeMap<
                Vec<u8>,
                ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTreePair>,
            >,
        ) -> ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTreePair> {
            let [first, second] = <[_; 2]>::try_from(buckets).unwrap();
            let key = EvidenceTreeEntry::node_key(buckets);
            if let Some(pcd) = pairs.get(&key) {
                return pcd.clone();
            }
            let (pcd, ()) = app
                .fuse(
                    rng,
                    evidence::EvidenceTreeLeafPair,
                    (),
                    first.pcd.clone(),
                    second.pcd.clone(),
                )
                .unwrap();
            pairs.insert(key, pcd.clone());
            pcd
        }

        fn pair_fuse<RNG: CryptoRng>(
            rng: &mut RNG,
            app: &App<'_>,
            buckets: &[&QrBucketEntry],
            left: ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>,
            right: ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>,
            pairs: &mut BTreeMap<
                Vec<u8>,
                ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTreePair>,
            >,
        ) -> ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTreePair> {
            let key = EvidenceTreeEntry::node_key(buckets);
            if let Some(pcd) = pairs.get(&key) {
                return pcd.clone();
            }
            let (pcd, ()) = app
                .fuse(rng, evidence::EvidenceTreePairFuse, (), left, right)
                .unwrap();
            pairs.insert(key, pcd.clone());
            pcd
        }

        fn node<RNG: CryptoRng>(
            rng: &mut RNG,
            app: &App<'_>,
            buckets: &[&QrBucketEntry],
            pairs: &mut BTreeMap<
                Vec<u8>,
                ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTreePair>,
            >,
            trees: &mut BTreeMap<Vec<u8>, ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>>,
        ) -> (
            ragu::Pcd<Pasta, ProductionRank, evidence::EvidenceTree>,
            Vec<EvidenceLeaf>,
        ) {
            let (left, right, leaves) = if buckets.len() == EVIDENCE_TREE_ARITY {
                let left = leaf_pair(rng, app, &buckets[..2], pairs);
                let right = leaf_pair(rng, app, &buckets[2..], pairs);
                let roots = [left.data().4, left.data().5, right.data().4, right.data().5];
                let leaves = buckets
                    .iter()
                    .enumerate()
                    .map(|(index, bucket)| EvidenceLeaf {
                        index,
                        header: *bucket.pcd.data(),
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
                    .map(|part| node(rng, app, part, pairs, trees))
                    .collect::<Vec<_>>();
                let roots = [
                    children[0].0.data().4,
                    children[1].0.data().4,
                    children[2].0.data().4,
                    children[3].0.data().4,
                ];
                let half = buckets.len() / 2;
                let left = pair_fuse(
                    rng,
                    app,
                    &buckets[..half],
                    children[0].0.clone(),
                    children[1].0.clone(),
                    pairs,
                );
                let right = pair_fuse(
                    rng,
                    app,
                    &buckets[half..],
                    children[2].0.clone(),
                    children[3].0.clone(),
                    pairs,
                );
                let leaves = children
                    .into_iter()
                    .enumerate()
                    .flat_map(|(digit, (_, leaves))| {
                        leaves.into_iter().map(move |mut leaf| {
                            leaf.index += digit * child_width;
                            leaf.path
                                .insert(0, ([digit & 2 != 0, digit & 1 != 0], roots));
                            leaf
                        })
                    })
                    .collect::<Vec<_>>();
                (left, right, leaves)
            };
            let key = EvidenceTreeEntry::node_key(buckets);
            let pcd = trees.get(&key).map_or_else(
                || {
                    let (pcd, ()) = app
                        .fuse(rng, evidence::EvidenceTreeFuse, (), left, right)
                        .unwrap();
                    pcd
                },
                Clone::clone,
            );
            trees.insert(key, pcd.clone());
            (pcd, leaves)
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
        let mut pairs = BTreeMap::new();
        let mut trees = BTreeMap::new();
        let (mut pcd, mut leaves) = node(rng, app, &padded, &mut pairs, &mut trees);
        let mut cap_count = 0u32;
        while !(depth + usize::try_from(cap_count).unwrap())
            .is_multiple_of(evidence::EvidenceTreeDescend::LEVELS)
        {
            let child = pcd.data().4;
            let (raised, ()) = app
                .fuse(
                    rng,
                    evidence::EvidenceTreeCap,
                    (),
                    pcd,
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            pcd = raised;
            for leaf in &mut leaves {
                leaf.path
                    .insert(0, ([false, false], [child; EVIDENCE_TREE_ARITY]));
            }
            cap_count += 1;
        }
        Self {
            pcd,
            leaves,
            real_leaves: buckets.len(),
        }
    }

    pub(crate) fn build_with_scales<RNG: CryptoRng>(
        rng: &mut RNG,
        app: &App<'_>,
        buckets: &[QrBucketEntry],
        mut scales: Vec<Fp>,
    ) -> Self {
        assert!(!buckets.is_empty());
        assert_eq!(buckets.len(), scales.len());
        let mut tree = Self::build(rng, app, buckets);
        scales.resize(tree.leaves.len(), *scales.last().unwrap());
        for (leaf, scale) in tree.leaves.iter_mut().zip(scales) {
            leaf.contents = scaled_qr_contents(&leaf.members, scale);
        }
        tree
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
            witness::evidence_tree_open((*node.data(), ()), leaf.profile(), leaf.contents.clone());
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
