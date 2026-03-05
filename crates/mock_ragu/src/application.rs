//! Mock PCD application — entry point for proof creation and verification.
//!
//! Mirrors `ragu_pcd::Application` and `ragu_pcd::ApplicationBuilder`.
//! The builder pattern registers steps, then finalizes into an application
//! that can seed, fuse, and verify proofs.

use rand::CryptoRng;

use crate::{
    error::ValidationError,
    header::Header,
    proof::{self, PROOF_SIZE, Pcd, Proof},
    step::Step,
};

/// Builder for constructing a mock PCD [`Application`].
///
/// Mirrors `ragu_pcd::ApplicationBuilder`. In real Ragu, building an
/// application compiles circuits and sets up proving parameters. In the
/// mock, registration is a no-op.
#[derive(Clone, Copy, Debug)]
pub struct ApplicationBuilder;

/// A mock PCD application.
///
/// Mirrors `ragu_pcd::Application`. Provides [`seed`](Self::seed),
/// [`fuse`](Self::fuse), [`verify`](Self::verify), and
/// [`rerandomize`](Self::rerandomize) operations.
#[derive(Clone, Copy, Debug)]
pub struct Application;

impl ApplicationBuilder {
    /// Creates a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Registers a step with this application.
    ///
    /// In real Ragu, this compiles the step's circuit. In the mock,
    /// it is a no-op.
    pub fn register<S: Step>(self, _step: S) -> Result<Self, ValidationError> {
        Ok(self)
    }

    /// Finalizes the builder into an [`Application`].
    pub const fn finalize(self) -> Result<Application, ValidationError> {
        Ok(Application)
    }
}

impl Default for ApplicationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Application {
    /// Creates a leaf proof (no prior proofs).
    ///
    /// Mirrors `ragu_pcd::Application::seed`. The step's `Left` and `Right`
    /// must both be `()` (trivial header), since there are no input proofs.
    ///
    /// Calls the step's [`witness`](Step::witness) to compute the output
    /// header data, then constructs a proof binding that data.
    pub fn seed<'source, RNG: CryptoRng, S: Step<Left = (), Right = ()>>(
        &self,
        _rng: &mut RNG,
        step: &S,
        witness: S::Witness<'source>,
    ) -> Result<(Proof, S::Aux<'source>), ValidationError> {
        let (output_data, aux) = step.witness(witness, (), ())?;

        let encoded = S::Output::encode(&output_data);
        let header_hash = proof::compute_header_hash(&encoded);
        let witness_hash = proof::compute_witness_hash(&encoded);
        let merge_tag = [0u8; 32];

        let proof_value = proof::assemble(&header_hash, &witness_hash, &merge_tag);
        Ok((proof_value, aux))
    }

    /// Merges two proofs (PCD fuse).
    ///
    /// Mirrors `ragu_pcd::Application::fuse`. Takes two input PCDs and
    /// a merge step, producing a combined proof.
    pub fn fuse<'source, RNG: CryptoRng, S: Step>(
        &self,
        _rng: &mut RNG,
        step: &S,
        witness: S::Witness<'source>,
        left: Pcd<'source, S::Left>,
        right: Pcd<'source, S::Right>,
    ) -> Result<(Proof, S::Aux<'source>), ValidationError> {
        let left_proof = left.proof;
        let right_proof = right.proof;
        let (output_data, aux) = step.witness(witness, left.data, right.data)?;

        let encoded = S::Output::encode(&output_data);
        let header_hash = proof::compute_header_hash(&encoded);

        // Witness hash: hash both child proofs
        let left_bytes: [u8; PROOF_SIZE] = left_proof.into();
        let right_bytes: [u8; PROOF_SIZE] = right_proof.into();
        let witness_hash_val = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"MkRagu_Witness_\0")
            .to_state()
            .update(&left_bytes)
            .update(&right_bytes)
            .finalize();
        let mut witness_hash = [0u8; 32];
        witness_hash.copy_from_slice(witness_hash_val.as_bytes());

        // Merge tag: hash of children's bindings
        let merge_tag = proof::compute_merge_tag(&left_proof.binding(), &right_proof.binding());

        let proof_value = proof::assemble(&header_hash, &witness_hash, &merge_tag);
        Ok((proof_value, aux))
    }

    /// Verifies a proof against its carried header data.
    ///
    /// Mirrors `ragu_pcd::Application::verify`. Recomputes the header
    /// hash from the PCD's data and checks the proof's binding.
    pub fn verify<RNG: CryptoRng, H: Header>(
        &self,
        pcd: &Pcd<'_, H>,
        _rng: RNG,
    ) -> Result<bool, ValidationError> {
        // Recompute header hash from the carried data
        let encoded = H::encode(&pcd.data);
        let expected_header_hash = proof::compute_header_hash(&encoded);

        if expected_header_hash != pcd.proof.header_hash() {
            return Ok(false);
        }

        // Verify binding consistency
        let expected_binding = proof::compute_binding(
            &pcd.proof.header_hash(),
            &pcd.proof.witness_hash(),
            &pcd.proof.merge_tag(),
        );

        Ok(expected_binding == pcd.proof.binding())
    }

    /// Rerandomizes a proof (no-op in mock).
    ///
    /// In real Ragu, this rerandomizes polynomial commitments for
    /// unlinkability. The mock returns the same PCD unchanged.
    pub fn rerandomize<'source, RNG: CryptoRng, H: Header>(
        &self,
        pcd: Pcd<'source, H>,
        _rng: &mut RNG,
    ) -> Result<Pcd<'source, H>, ValidationError> {
        Ok(pcd)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use rand::thread_rng;

    use super::*;
    use crate::{header::Suffix, step::Index};

    // -- Test header: carries a single u64 value ----------------------------

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

    // -- Test seed step: creates a leaf from a u64 witness ------------------

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
        ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>), ValidationError>
        {
            Ok((TestHeaderData { value: witness }, ()))
        }
    }

    // -- Test merge step: sums two header values ----------------------------

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
        ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>), ValidationError>
        {
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

        let valid = app.verify(&pcd, thread_rng()).expect("verify should succeed");
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
        // Carry wrong data
        let pcd = proof.carry::<TestHeader>(TestHeaderData { value: 999 });

        let valid = app.verify(&pcd, thread_rng()).expect("verify should succeed");
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

        let (proof_a, ()) = app.seed(&mut thread_rng(), &SeedStep, 10u64).expect("seed a");
        let pcd_a = proof_a.carry::<TestHeader>(TestHeaderData { value: 10 });

        let (proof_b, ()) = app.seed(&mut thread_rng(), &SeedStep, 20u64).expect("seed b");
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
    fn rerandomize_preserves_validity() {
        let app = ApplicationBuilder::new()
            .register(SeedStep)
            .expect("register should succeed")
            .finalize()
            .expect("finalize should succeed");

        let (proof, ()) = app
            .seed(&mut thread_rng(), &SeedStep, 42u64)
            .expect("seed should succeed");
        let pcd = proof.carry::<TestHeader>(TestHeaderData { value: 42 });

        let rerand_pcd = app
            .rerandomize(pcd, &mut thread_rng())
            .expect("rerandomize should succeed");
        let valid = app
            .verify(&rerand_pcd, thread_rng())
            .expect("verify should succeed");
        assert!(valid, "rerandomized proof should still verify");
    }
}
