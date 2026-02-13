//! Stamp circuit for the Ragu PCD proving system.
//!
//! The stamp circuit verifies all actions in a bundle using a PCD
//! (Proof-Carrying Data) tree:
//!
//! - **[`ActionLeaf`]** (Index 0) — verifies a single tachyaction
//! - **[`StampMerge`]** (Index 1) — combines two sub-proofs
//!
//! Tachyon unifies spend and output operations: "regardless of the
//! operation a `(cv, rk)` pair are produced." A single [`ActionLeaf`]
//! circuit handles both — all differences live in the private witness,
//! not the circuit structure. This preserves tachygram
//! indistinguishability.
//!
//! ## PCD Tree
//!
//! ```text
//!  ActionLeaf    ActionLeaf    <-- one per tachyaction
//!  (action_0)    (action_1)
//!       \          /
//!        StampMerge            <-- final proof
//! ```
//!
//! ## Two Accumulators
//!
//! The proof produces two **Pedersen multiset hash** accumulators as
//! public outputs.  Each is a curve point (on the Pallas curve):
//!
//! - **$\hat{d}$** — accumulates action digests $[\text{Poseidon}(rk_i \| cv_i)] \cdot G_{acc}$
//! - **$\widehat{Tg}$** — accumulates hashed tachygrams $[\text{Poseidon}(tg_i)] \cdot G_{acc}$
//!
//! Each element is hashed (Poseidon) then mapped to a Pallas point via
//! scalar multiplication against a fixed generator $G_{acc}$ — this is
//! "free" in the curve cycle since $\mathbb{F}_p$ is the Pallas scalar
//! field.  The accumulator is the EC sum of those points:
//!
//! $$\hat{d} = \sum [\text{Poseidon}(rk_i \| cv_i)] \cdot G_{acc}$$
//! $$\widehat{Tg} = \sum [\text{Poseidon}(tg_i)] \cdot G_{acc}$$
//!
//! Because EC point addition is commutative, the PCD tree shape is
//! irrelevant.  The merge step uses incomplete addition
//! ([`Point::add_incomplete`]).
//!
//! The verifier pre-computes the expected accumulators from public data
//! and checks the final header:
//!
//! $$\text{expected\_actions\_acc} = \sum [\text{Poseidon}(rk_i \| cv_i)] \cdot G_{acc}$$
//! $$\text{expected\_tachygram\_acc} = \sum [\text{Poseidon}(tg_i)] \cdot G_{acc}$$
//!
//! The **proof** is what binds $\hat{d}$ to $\widehat{Tg}$ — without it, there is no way
//! to verify that a particular $rk$ corresponds to a particular
//! tachygram.  The recursive SNARK verifier sees only $(\hat{d}, \widehat{Tg},
//! anchor)$, never individual $rk$, $cv$, or tachygram values.
//!
//! ## Header: [`StampDigest`]
//!
//! The succinct state carried through the PCD tree.  Five field
//! elements: two curve points (x, y each) plus one scalar.
//!
//! | Field    | Type          | Elements | Description |
//! |----------|---------------|----------|-------------|
//! | `actions_acc`  | Pallas point  | 2 (x,y) | Pedersen multiset hash over action digests |
//! | `tachygram_acc` | Pallas point  | 2 (x,y) | Pedersen multiset hash over tachygrams |
//! | `anchor` | Fp scalar     | 1        | Epoch — must agree across all actions |
//!
//! ## Verification (out-of-circuit)
//!
//! 1. Check each $\sigma_i$ against $rk_i$ (RedPallas)
//! 2. $\text{actions\_acc} = \sum [\text{Poseidon}(rk_i \| cv_i)] \cdot G_{acc}$ (pre-process)
//! 3. $\text{tachygram\_acc} = \sum [\text{Poseidon}(tg_i)] \cdot G_{acc}$ (pre-process)
//! 4. $\text{verify}(proof, header = (\text{actions\_acc}, \text{tachygram\_acc}, anchor))$
//! 5. Check binding sig against $\sum cv_i$ (RedPallas)
//!
//! ## Hash-to-Curve
//!
//! The in-circuit hash-to-curve mapping ($\mathbb{F}_p \to$ Pallas point)
//! exploits the Pasta curve cycle: $\mathbb{F}_p$ is the scalar field of
//! Pallas, so mapping is just scalar multiplication against a fixed
//! generator.  `Endoscalar::extract` bridges $\mathbb{F}_p \to \mathbb{F}_q$
//! and `group_scale` performs $[h] \cdot G_{acc}$.

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::Result;

use crate::primitives::Fp;

mod step;

mod header;
mod witnesses;

pub use header::StampDigestData;
pub use witnesses::{ActionWitness, MergeWitness};

use step::{ActionLeaf, StampMerge};

// ═══════════════════════════════════════════════════════════════════════
// Application builder
// ═══════════════════════════════════════════════════════════════════════

/// Convenience wrapper for building a stamp PCD application.
///
/// Registers the two steps ([`ActionLeaf`], [`StampMerge`]) and
/// returns a configured [`ragu_pcd::Application`].
///
/// # Usage
///
/// ```ignore
/// use ragu_pasta::Pasta;
///
/// let params = Pasta::baked();
/// let app = TachystampApp::build::<Pasta, R>(params)?;
///
/// // Create leaf proofs (same step for spends and outputs)
/// let (pcd_0, tg_0) = app.seed(&mut rng, action_leaf, witness_0)?;
/// let (pcd_1, tg_1) = app.seed(&mut rng, action_leaf, witness_1)?;
///
/// // Merge into a single stamp proof
/// let stamp_pcd = app.fuse(&mut rng, merge, merge_witness, pcd_0, pcd_1)?;
/// ```
#[allow(missing_debug_implementations)]
pub struct TachystampApp;

impl TachystampApp {
    /// Header size for the stamp circuit.
    ///
    /// Five field elements: two curve points `(actions_acc.x, actions_acc.y,
    /// tachygram_acc.x, tachygram_acc.y)` and one scalar `(anchor)`.
    pub const HEADER_SIZE: usize = 5;

    /// Builds the stamp PCD application.
    ///
    /// Registers `ActionLeaf` (0) and `StampMerge` (1).
    pub fn build<C, R>(
        params: &C::Params,
    ) -> Result<ragu_pcd::Application<'_, C, R, { Self::HEADER_SIZE }>>
    where
        C: Cycle<CircuitField = Fp>,
        R: Rank,
    {
        let poseidon = C::circuit_poseidon(params);

        let builder = ragu_pcd::ApplicationBuilder::new();
        let builder = builder.register(ActionLeaf::<C> { poseidon })?;
        let builder = builder.register(StampMerge::<C> { poseidon })?;
        builder.finalize(params)
    }
}
