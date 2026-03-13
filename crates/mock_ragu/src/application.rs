//! Mock PCD application — mirrors `ragu_pcd::Application`.

use alloc::vec::Vec;

use rand_core::CryptoRng;

use crate::{
    error::Result,
    header::Header,
    proof::{self, PROOF_SIZE_COMPRESSED, Pcd, Proof},
    step::Step,
};

/// Mocks `ragu_pcd::ApplicationBuilder`.
#[derive(Clone, Copy, Debug)]
pub struct ApplicationBuilder;

/// Mocks `ragu_pcd::Application`.
#[derive(Clone, Copy, Debug)]
pub struct Application;

impl ApplicationBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn register<S: Step>(self, _step: S) -> Result<Self> {
        Ok(self)
    }

    pub fn finalize(self) -> Result<Application> {
        Ok(Application)
    }
}

impl Default for ApplicationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Application {
    /// Delegates to [`fuse`](Self::fuse) with trivial PCDs.
    pub fn seed<'source, RNG: CryptoRng, S: Step<Left = (), Right = ()>>(
        &self,
        rng: &mut RNG,
        step: &S,
        witness: S::Witness<'source>,
    ) -> Result<(Proof, S::Aux<'source>)> {
        let left = Proof::trivial().carry::<()>(());
        let right = Proof::trivial().carry::<()>(());
        self.fuse(rng, step, witness, left, right)
    }

    pub fn fuse<'source, RNG: CryptoRng, S: Step>(
        &self,
        _rng: &mut RNG,
        step: &S,
        witness: S::Witness<'source>,
        left: Pcd<'source, S::Left>,
        right: Pcd<'source, S::Right>,
    ) -> Result<(Proof, S::Aux<'source>)> {
        let left_proof = left.proof;
        let right_proof = right.proof;
        let (output_data, aux) = step.witness(witness, left.data, right.data)?;

        let encoded = S::Output::encode(&output_data);

        // Witness data: concatenated serialized child proofs
        let left_bytes = left_proof.serialize();
        let right_bytes = right_proof.serialize();
        let mut witness_data = Vec::with_capacity(2 * PROOF_SIZE_COMPRESSED);
        witness_data.extend_from_slice(left_bytes.as_ref());
        witness_data.extend_from_slice(right_bytes.as_ref());

        let proof_value = Proof::new(&encoded, &witness_data);
        Ok((proof_value, aux))
    }

    pub fn verify<RNG: CryptoRng, H: Header>(&self, pcd: &Pcd<'_, H>, _rng: RNG) -> Result<bool> {
        // Recompute header hash from the carried data
        let encoded = H::encode(&pcd.data);
        let expected_header_hash = proof::compute_header_hash(&encoded);

        if expected_header_hash != pcd.proof.header_hash {
            return Ok(false);
        }

        // Verify binding consistency
        let expected_binding =
            proof::compute_binding(&pcd.proof.header_hash, &pcd.proof.witness_hash);

        Ok(expected_binding == pcd.proof.binding)
    }

    pub fn rerandomize<'source, RNG: CryptoRng, H: Header>(
        &self,
        pcd: Pcd<'source, H>,
        _rng: &mut RNG,
    ) -> Result<Pcd<'source, H>> {
        Ok(Pcd {
            proof: pcd.proof.rerandomize(),
            data: pcd.data,
        })
    }
}
