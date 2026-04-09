use alloc::vec::Vec;

use rand::thread_rng;

use super::{
    application::*,
    error::Result,
    header::{Header, Suffix},
    proof::{PROOF_SIZE_COMPRESSED, Pcd, Proof},
    step::{Index, Step},
};

// ---- proof ----

#[test]
fn proof_round_trip() {
    let proof = Proof::new(b"header", b"witness");
    let bytes: [u8; PROOF_SIZE_COMPRESSED] = proof.clone().into();
    let recovered = Proof::try_from(&bytes).expect("round trip should succeed");
    assert_eq!(proof, recovered);
}

#[test]
fn tampered_proof_fails() {
    let proof = Proof::new(b"header", b"witness");
    let mut bytes: [u8; PROOF_SIZE_COMPRESSED] = proof.into();
    bytes[0] ^= 0xFFu8;
    Proof::try_from(&bytes).expect_err("tampered proof should fail");
}

#[test]
fn carry_creates_pcd() {
    let proof = Proof::new(b"header", b"witness");
    let expected = proof.clone();
    let pcd: Pcd<'_, ()> = proof.carry(());
    assert_eq!(pcd.proof, expected);
}

#[test]
fn rerandomize() {
    let proof = Proof::new(b"header", b"witness");
    assert_eq!(proof.rerand_tag, [0u8; 32]);

    let once = proof.rerandomize();

    assert_eq!(proof.header_hash, once.header_hash);
    assert_eq!(proof.witness_hash, once.witness_hash);
    assert_eq!(proof.binding, once.binding);
    assert_ne!(proof, once);

    let twice = once.rerandomize();
    assert_eq!(proof.header_hash, twice.header_hash);
    assert_eq!(proof.witness_hash, twice.witness_hash);
    assert_eq!(proof.binding, twice.binding);
    assert_ne!(once, twice);

    assert_ne!(proof.rerand_tag, once.rerand_tag);
    assert_ne!(proof.rerand_tag, twice.rerand_tag);
    assert_ne!(once.rerand_tag, twice.rerand_tag);
}

// ---- application ----

struct TestHeader;

#[derive(Clone, Debug)]
struct TestHeaderData {
    value: u64,
}

impl Header for TestHeader {
    type Data<'source> = TestHeaderData;

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        #[expect(clippy::little_endian_bytes, reason = "test encoding")]
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

    let (proof, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 42u64)
        .expect("seed should succeed");
    let pcd = proof.carry::<TestHeader>(TestHeaderData { value: 42 });

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

    let (proof, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 42u64)
        .expect("seed should succeed");
    let pcd = proof.carry::<TestHeader>(TestHeaderData { value: 999 });

    let valid = app
        .verify(&pcd, thread_rng())
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

    let (proof_a, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 10u64)
        .expect("seed a");
    let pcd_a = proof_a.carry::<TestHeader>(TestHeaderData { value: 10 });

    let (proof_b, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 20u64)
        .expect("seed b");
    let pcd_b = proof_b.carry::<TestHeader>(TestHeaderData { value: 20 });

    let (merged_proof, ()) = app
        .fuse(&mut thread_rng(), &MergeStep, (), pcd_a, pcd_b)
        .expect("fuse should succeed");
    let merged_pcd = merged_proof.carry::<TestHeader>(TestHeaderData { value: 30 });

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

    let (proof_a, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 10u64)
        .expect("seed a");
    let pcd_a = proof_a.carry::<TestHeader>(TestHeaderData { value: 10 });

    let (proof_b, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 20u64)
        .expect("seed b");
    let pcd_b = proof_b.carry::<TestHeader>(TestHeaderData { value: 20 });

    let (merged_proof, ()) = app
        .fuse(&mut thread_rng(), &MergeStep, (), pcd_a, pcd_b)
        .expect("fuse");
    let bad_pcd = merged_proof.carry::<TestHeader>(TestHeaderData { value: 31 });

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

    let mut proofs = Vec::new();
    for val in 1u64..=4 {
        let (proof, ()) = app.seed(&mut thread_rng(), &SeedStep, val).expect("seed");
        proofs.push((proof, val));
    }

    let (p1, v1) = proofs.remove(0);
    let (p2, v2) = proofs.remove(0);
    let pcd1 = p1.carry::<TestHeader>(TestHeaderData { value: v1 });
    let pcd2 = p2.carry::<TestHeader>(TestHeaderData { value: v2 });
    let (merged_left, ()) = app
        .fuse(&mut thread_rng(), &MergeStep, (), pcd1, pcd2)
        .expect("fuse left");

    let (p3, v3) = proofs.remove(0);
    let (p4, v4) = proofs.remove(0);
    let pcd3 = p3.carry::<TestHeader>(TestHeaderData { value: v3 });
    let pcd4 = p4.carry::<TestHeader>(TestHeaderData { value: v4 });
    let (merged_right, ()) = app
        .fuse(&mut thread_rng(), &MergeStep, (), pcd3, pcd4)
        .expect("fuse right");

    let pcd_left = merged_left.carry::<TestHeader>(TestHeaderData { value: v1 + v2 });
    let pcd_right = merged_right.carry::<TestHeader>(TestHeaderData { value: v3 + v4 });
    let (final_proof, ()) = app
        .fuse(&mut thread_rng(), &MergeStep, (), pcd_left, pcd_right)
        .expect("fuse final");

    let final_pcd = final_proof.carry::<TestHeader>(TestHeaderData { value: 10 });
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

    let (pa, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 1u64)
        .expect("seed a");
    let (pb, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 2u64)
        .expect("seed b");
    let (pc, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 3u64)
        .expect("seed c");

    // Tree shape 1: fuse(fuse(a, b), c)
    let pcd_a1 = pa.clone().carry::<TestHeader>(TestHeaderData { value: 1 });
    let pcd_b1 = pb.clone().carry::<TestHeader>(TestHeaderData { value: 2 });
    let (ab, ()) = app
        .fuse(&mut thread_rng(), &MergeStep, (), pcd_a1, pcd_b1)
        .expect("fuse ab");
    let pcd_ab = ab.carry::<TestHeader>(TestHeaderData { value: 3 });
    let pcd_c1 = pc.clone().carry::<TestHeader>(TestHeaderData { value: 3 });
    let (left_leaning, ()) = app
        .fuse(&mut thread_rng(), &MergeStep, (), pcd_ab, pcd_c1)
        .expect("fuse (ab)c");

    // Tree shape 2: fuse(a, fuse(b, c))
    let pcd_b2 = pb.carry::<TestHeader>(TestHeaderData { value: 2 });
    let pcd_c2 = pc.carry::<TestHeader>(TestHeaderData { value: 3 });
    let (bc, ()) = app
        .fuse(&mut thread_rng(), &MergeStep, (), pcd_b2, pcd_c2)
        .expect("fuse bc");
    let pcd_a2 = pa.carry::<TestHeader>(TestHeaderData { value: 1 });
    let pcd_bc = bc.carry::<TestHeader>(TestHeaderData { value: 5 });
    let (right_leaning, ()) = app
        .fuse(&mut thread_rng(), &MergeStep, (), pcd_a2, pcd_bc)
        .expect("fuse a(bc)");

    let final_header = TestHeaderData { value: 6 };

    let pcd_left = left_leaning.carry::<TestHeader>(final_header.clone());
    let pcd_right = right_leaning.carry::<TestHeader>(final_header);

    assert!(app.verify(&pcd_left, thread_rng()).expect("verify"));
    assert!(app.verify(&pcd_right, thread_rng()).expect("verify"));
    assert_ne!(
        pcd_left.proof, pcd_right.proof,
        "different tree shapes must produce different proofs"
    );
}

// -- Steps with aux --

/// Header value is `witness²`, aux is `alloc::vec![witness²]`.
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

    let (proof_a, aux_a) = app
        .seed(&mut thread_rng(), &AuxSeedStep, 3u64)
        .expect("seed a");
    assert_eq!(aux_a, alloc::vec![9]);

    let (proof_b, aux_b) = app
        .seed(&mut thread_rng(), &AuxSeedStep, 4u64)
        .expect("seed b");
    assert_eq!(aux_b, alloc::vec![16]);

    let pcd_a = proof_a.carry::<TestHeader>(TestHeaderData { value: 9 });
    let pcd_b = proof_b.carry::<TestHeader>(TestHeaderData { value: 16 });
    let (merged_proof, merged_aux) = app
        .fuse(
            &mut thread_rng(),
            &AuxMergeStep,
            (aux_a, aux_b),
            pcd_a,
            pcd_b,
        )
        .expect("fuse");

    assert_eq!(merged_aux, alloc::vec![9, 16]);

    let reconstructed_value: u64 = merged_aux.iter().sum();
    assert_eq!(reconstructed_value, 25);
    let pcd = merged_proof.carry::<TestHeader>(TestHeaderData {
        value: reconstructed_value,
    });
    let valid = app.verify(&pcd, thread_rng()).expect("verify");
    assert!(
        valid,
        "proof must verify with header reconstructed from aux"
    );
}

#[test]
fn rerandomize_preserves_validity() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (proof, ()) = app
        .seed(&mut thread_rng(), &SeedStep, 42u64)
        .expect("seed should succeed");
    let original_proof = proof.clone();
    let pcd = proof.carry::<TestHeader>(TestHeaderData { value: 42 });

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
