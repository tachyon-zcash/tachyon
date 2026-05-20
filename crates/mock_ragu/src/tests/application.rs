use alloc::vec::Vec;

use rand::thread_rng;

use crate::{
    application::*,
    error::Result,
    header::{Header, Suffix},
    proof::{PROOF_SIZE_COMPRESSED, Proof},
    step::{Index, Step},
};

struct TestHeader;

#[derive(Clone, Debug)]
struct TestHeaderData {
    value: u64,
}

impl Header for TestHeader {
    type Data<'source> = TestHeaderData;

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let bytes = data.value.to_le_bytes();
        bytes.to_vec()
    }
}

struct SeedStep;

impl Step for SeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = u64;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        Ok((TestHeaderData { value: witness }, ()))
    }
}

struct MergeStep;

impl Step for MergeStep {
    type Aux<'source> = ();
    type Left = TestHeader;
    type Output = TestHeader;
    type Right = TestHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        Ok((
            TestHeaderData {
                value: left.value + right.value,
            },
            (),
        ))
    }
}

#[test]
fn seed_then_verify() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut thread_rng(), SeedStep, 42u64)
        .expect("seed should succeed");

    let valid = app
        .verify(&pcd, thread_rng())
        .expect("verify should succeed");
    assert!(valid, "proof should verify against matching header data");
}

#[test]
fn verify_rejects_wrong_data() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut thread_rng(), SeedStep, 42u64)
        .expect("seed should succeed");
    let bad_pcd = pcd.proof.carry::<TestHeader>(TestHeaderData { value: 999 });

    let valid = app
        .verify(&bad_pcd, thread_rng())
        .expect("verify should succeed");
    assert!(!valid, "proof should reject mismatched header data");
}

#[test]
fn fuse_then_verify() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .register(MergeStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd_a, ()) = app
        .seed(&mut thread_rng(), SeedStep, 10u64)
        .expect("seed a");
    let (pcd_b, ()) = app
        .seed(&mut thread_rng(), SeedStep, 20u64)
        .expect("seed b");

    let (merged_pcd, ()) = app
        .fuse(&mut thread_rng(), MergeStep, (), pcd_a, pcd_b)
        .expect("fuse should succeed");

    let valid = app
        .verify(&merged_pcd, thread_rng())
        .expect("verify should succeed");
    assert!(valid, "merged proof should verify");
}

#[test]
fn fuse_rejects_wrong_sum() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register")
        .register(MergeStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (pcd_a, ()) = app
        .seed(&mut thread_rng(), SeedStep, 10u64)
        .expect("seed a");
    let (pcd_b, ()) = app
        .seed(&mut thread_rng(), SeedStep, 20u64)
        .expect("seed b");

    let (merged_pcd, ()) = app
        .fuse(&mut thread_rng(), MergeStep, (), pcd_a, pcd_b)
        .expect("fuse");
    let bad_pcd = merged_pcd
        .proof
        .carry::<TestHeader>(TestHeaderData { value: 31 });

    let valid = app.verify(&bad_pcd, thread_rng()).expect("verify");
    assert!(!valid, "fused proof must reject wrong header data");
}

#[test]
fn deep_fuse_chain() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register")
        .register(MergeStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let mut pcds = Vec::new();
    for val in 1u64..=4 {
        let (pcd, ()) = app.seed(&mut thread_rng(), SeedStep, val).expect("seed");
        pcds.push(pcd);
    }

    let pcd1 = pcds.remove(0);
    let pcd2 = pcds.remove(0);
    let (merged_left, ()) = app
        .fuse(&mut thread_rng(), MergeStep, (), pcd1, pcd2)
        .expect("fuse left");

    let pcd3 = pcds.remove(0);
    let pcd4 = pcds.remove(0);
    let (merged_right, ()) = app
        .fuse(&mut thread_rng(), MergeStep, (), pcd3, pcd4)
        .expect("fuse right");

    let (final_pcd, ()) = app
        .fuse(&mut thread_rng(), MergeStep, (), merged_left, merged_right)
        .expect("fuse final");

    assert!(
        app.verify(&final_pcd, thread_rng()).expect("verify"),
        "depth-2 fuse tree must verify"
    );

    let bad_pcd = final_pcd
        .proof
        .carry::<TestHeader>(TestHeaderData { value: 11 });
    assert!(
        !app.verify(&bad_pcd, thread_rng()).expect("verify"),
        "wrong total must fail"
    );
}

#[test]
fn different_merge_trees_same_header() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register")
        .register(MergeStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (pa, ()) = app.seed(&mut thread_rng(), SeedStep, 1u64).expect("seed a");
    let (pb, ()) = app.seed(&mut thread_rng(), SeedStep, 2u64).expect("seed b");
    let (pc, ()) = app.seed(&mut thread_rng(), SeedStep, 3u64).expect("seed c");

    // Tree shape 1: fuse(fuse(a, b), c)
    let (ab, ()) = app
        .fuse(&mut thread_rng(), MergeStep, (), pa.clone(), pb.clone())
        .expect("fuse ab");
    let (left_leaning, ()) = app
        .fuse(&mut thread_rng(), MergeStep, (), ab, pc.clone())
        .expect("fuse (ab)c");

    // Tree shape 2: fuse(a, fuse(b, c))
    let (bc, ()) = app
        .fuse(&mut thread_rng(), MergeStep, (), pb, pc)
        .expect("fuse bc");
    let (right_leaning, ()) = app
        .fuse(&mut thread_rng(), MergeStep, (), pa, bc)
        .expect("fuse a(bc)");

    assert!(app.verify(&left_leaning, thread_rng()).expect("verify"));
    assert!(app.verify(&right_leaning, thread_rng()).expect("verify"));
    assert_ne!(
        left_leaning.proof, right_leaning.proof,
        "different tree shapes must produce different proofs"
    );
}

/// Header value is `witness²`, aux is `vec![witness²]`.
struct AuxSeedStep;

impl Step for AuxSeedStep {
    type Aux<'source> = Vec<u64>;
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = u64;

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let squared = witness * witness;
        Ok((TestHeaderData { value: squared }, alloc::vec![squared]))
    }
}

struct AuxMergeStep;

impl Step for AuxMergeStep {
    type Aux<'source> = Vec<u64>;
    type Left = TestHeader;
    type Output = TestHeader;
    type Right = TestHeader;
    type Witness<'source> = (Vec<u64>, Vec<u64>);

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let (left_aux, right_aux) = witness;
        let mut combined = left_aux;
        combined.extend(right_aux);
        Ok((
            TestHeaderData {
                value: left.value + right.value,
            },
            combined,
        ))
    }
}

#[test]
fn aux_data_flows_through_seed_and_fuse() {
    let app = ApplicationBuilder::new()
        .register(AuxSeedStep)
        .expect("register")
        .register(AuxMergeStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (pcd_a, aux_a) = app
        .seed(&mut thread_rng(), AuxSeedStep, 3u64)
        .expect("seed a");
    assert_eq!(aux_a, alloc::vec![9]);

    let (pcd_b, aux_b) = app
        .seed(&mut thread_rng(), AuxSeedStep, 4u64)
        .expect("seed b");
    assert_eq!(aux_b, alloc::vec![16]);

    let (merged_pcd, merged_aux) = app
        .fuse(
            &mut thread_rng(),
            AuxMergeStep,
            (aux_a, aux_b),
            pcd_a,
            pcd_b,
        )
        .expect("fuse");

    assert_eq!(merged_aux, alloc::vec![9, 16]);
    let reconstructed_value: u64 = merged_aux.iter().sum();
    assert_eq!(reconstructed_value, 25);
    let valid = app.verify(&merged_pcd, thread_rng()).expect("verify");
    assert!(valid, "fused proof must verify");
}

#[test]
fn serialized_proof_still_verifies() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut thread_rng(), SeedStep, 42u64)
        .expect("seed should succeed");
    let saved_data = pcd.data.clone();

    let bytes: [u8; PROOF_SIZE_COMPRESSED] = pcd.proof.into();
    let recovered_proof = Proof::try_from(&bytes).expect("recovered proof should deserialize");

    let recovered_pcd = recovered_proof.carry::<TestHeader>(saved_data);
    let valid = app
        .verify(&recovered_pcd, thread_rng())
        .expect("verify should succeed");
    assert!(valid, "round-tripped proof should still verify");
}

#[test]
fn serialized_proof_rejects_mismatched_header_data() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut thread_rng(), SeedStep, 42u64)
        .expect("seed should succeed");

    let bytes: [u8; PROOF_SIZE_COMPRESSED] = pcd.proof.into();
    let recovered_proof = Proof::try_from(&bytes).expect("recovered proof should deserialize");

    let bad_pcd = recovered_proof.carry::<TestHeader>(TestHeaderData { value: 999 });
    let valid = app
        .verify(&bad_pcd, thread_rng())
        .expect("verify should succeed");
    assert!(
        !valid,
        "round-tripped proof must still reject mismatched header data"
    );
}

#[test]
fn tampered_serialized_proof_fails_to_deserialize() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut thread_rng(), SeedStep, 42u64)
        .expect("seed should succeed");

    let mut bytes: [u8; PROOF_SIZE_COMPRESSED] = pcd.proof.into();
    bytes[0] ^= 0xFFu8;
    Proof::try_from(&bytes)
        .expect_err("tampered proof bytes must be rejected before reaching verify");
}

#[test]
fn rerandomize_preserves_validity() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut thread_rng(), SeedStep, 42u64)
        .expect("seed should succeed");
    let original_proof = pcd.proof.clone();

    let rerand_pcd = app
        .rerandomize(pcd, &mut thread_rng())
        .expect("rerandomize should succeed");
    let valid = app
        .verify(&rerand_pcd, thread_rng())
        .expect("verify should succeed");
    assert!(valid, "rerandomized proof should still verify");
    assert_ne!(
        rerand_pcd.proof, original_proof,
        "rerandomization must change the proof"
    );
}
