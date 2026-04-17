#![allow(unused_parens, reason = "pcd conventions")]

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::{EqAffine, Fp, group::GroupEncoding as _};
use rand::thread_rng;

use crate::{
    application::*,
    error::Result,
    gadgets::Multiset,
    header::{Header, Suffix},
    polynomial::*,
    proof::{Proof, Transcript},
    step::{Index, Step},
};

struct SetAccHeader;

impl Header for SetAccHeader {
    type Data<'source> = Commitment;

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let point: &EqAffine = data.inner();
        let point_bytes = point.to_bytes();
        point_bytes.to_vec()
    }
}

struct SeedSet;

impl Step for SeedSet {
    type Aux<'source> = (Multiset);
    type Left = ();
    type Output = SetAccHeader;
    type Right = ();
    type Witness<'source> = (Multiset);

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        Ok((witness.commit(), witness))
    }
}

struct MergeSets;

impl Step for MergeSets {
    type Aux<'source> = Multiset;
    type Left = SetAccHeader;
    type Output = SetAccHeader;
    type Right = SetAccHeader;
    type Witness<'source> = (Multiset, Multiset);

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let (left_handle, right_handle) = witness;

        assert_eq!(left_handle.commit(), left);
        assert_eq!(right_handle.commit(), right);

        let merged_handle = left_handle.merge(&right_handle);

        let mut transcript = Transcript::new(b"multiset-merge");
        transcript.absorb_commitment(&left_handle.commit());
        transcript.absorb_commitment(&right_handle.commit());
        transcript.absorb_commitment(&merged_handle.commit());
        let r = transcript.challenge();

        let p_r = left_handle.query(r);
        let q_r = right_handle.query(r);
        let s_r = merged_handle.query(r);
        if p_r * q_r != s_r {
            return Err(crate::error::Error);
        }

        Ok((merged_handle.commit(), merged_handle))
    }
}

struct CheckMembership;

impl Step for CheckMembership {
    type Aux<'source> = bool;
    type Left = SetAccHeader;
    type Output = SetAccHeader;
    type Right = ();
    type Witness<'source> = (Multiset, Fp);

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let (handle, target) = witness;

        assert_eq!(handle.commit(), left);

        let y = handle.query(target);
        let is_member = y == Fp::ZERO;

        Ok((left, is_member))
    }
}

#[test]
fn set_accumulator_tree_with_membership() {
    let app = ApplicationBuilder::new()
        .register(SeedSet)
        .expect("register atom")
        .register(MergeSets)
        .expect("register merge")
        .register(CheckMembership)
        .expect("register membership")
        .finalize()
        .expect("finalize");

    // 8 seed atoms × 4 elements each = 32-element set.
    let atoms: Vec<Vec<Fp>> = (0u64..8)
        .map(|i| {
            (0u64..4)
                .map(|j| Fp::from(i * 4 + j + 1))
                .collect::<Vec<_>>()
        })
        .collect();

    let all_elements: Vec<Fp> = atoms.iter().flatten().copied().collect();

    let mut leaves: Vec<(Proof, Multiset, Commitment)> = atoms
        .into_iter()
        .map(|elems| {
            let handle = Multiset::new(Polynomial::from_roots(&elems));
            let (proof, handle) = app.seed(&mut thread_rng(), &SeedSet, handle).expect("seed");
            let commitment = handle.commit();
            (proof, handle, commitment)
        })
        .collect();

    // Balanced binary tree fuse: 8 → 4 → 2 → 1.
    while leaves.len() > 1 {
        let mut next_level = Vec::new();
        for pair in leaves.chunks_exact(2) {
            let (left_proof, left_handle, left_commitment) = pair[0].clone();
            let (right_proof, right_handle, right_commitment) = pair[1].clone();

            let left_pcd = left_proof.carry::<SetAccHeader>(left_commitment);
            let right_pcd = right_proof.carry::<SetAccHeader>(right_commitment);

            let (merged_proof, merged_handle) = app
                .fuse(
                    &mut thread_rng(),
                    &MergeSets,
                    (left_handle, right_handle),
                    left_pcd,
                    right_pcd,
                )
                .expect("fuse");

            let merged_commitment = merged_handle.commit();
            next_level.push((merged_proof, merged_handle, merged_commitment));
        }
        leaves = next_level;
    }

    let (root_proof, root_handle, root_commitment) = leaves.into_iter().next().unwrap();

    // Verify root PCD.
    let root_pcd = root_proof.clone().carry::<SetAccHeader>(root_commitment);
    assert!(
        app.verify(&root_pcd, thread_rng()).expect("verify"),
        "root PCD must verify"
    );

    // Independently recompute the expected commitment.
    let expected_commitment = Polynomial::from_roots(&all_elements).commit(Fp::ZERO);
    assert_eq!(
        root_commitment, expected_commitment,
        "tree-computed commitment must match flat commitment"
    );

    // Membership: known member.
    let member = Fp::from(17u64);
    let left_pcd = root_proof.clone().carry::<SetAccHeader>(root_commitment);
    let right_pcd = Proof::trivial().carry::<()>(());
    let (_, is_member) = app
        .fuse(
            &mut thread_rng(),
            &CheckMembership,
            (root_handle.clone(), member),
            left_pcd,
            right_pcd,
        )
        .expect("membership query");
    assert!(is_member, "17 should be a member of the set");

    // Non-membership.
    let non_member = Fp::from(0u64);
    let left_pcd = root_proof.carry::<SetAccHeader>(root_commitment);
    let right_pcd = Proof::trivial().carry::<()>(());
    let (_, is_member) = app
        .fuse(
            &mut thread_rng(),
            &CheckMembership,
            (root_handle, non_member),
            left_pcd,
            right_pcd,
        )
        .expect("membership query");
    assert!(!is_member, "0 should not be a member of the set");
}
