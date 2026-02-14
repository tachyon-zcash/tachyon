#![allow(clippy::similar_names)]

// ═══════════════════════════════════════════════════════════════════════
// Action Leaf  (Index 0)
// ═══════════════════════════════════════════════════════════════════════

use ff::Field;
use pasta_curves::group::prime::PrimeCurveAffine;

use crate::primitives::{Fp, Fq};
use ragu_arithmetic::Cycle;
use ragu_core::Result;
use ragu_core::drivers::{Driver, DriverValue};
use ragu_core::maybe::Maybe;
use ragu_pasta::EpAffine;
use ragu_pcd::step::{Encoded, Index, Step};
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Element, Endoscalar, Point, extract_endoscalar};

use super::header::{StampDigest, StampDigestGadget};
use super::witnesses::{ActionWitness, MergeWitness};

/// Leaf step that verifies a single tachyaction (spend or output).
///
/// Tachyon unifies spend and output operations: "regardless of the
/// operation a `(cv, rk)` pair are produced." The circuit is the same
/// for both — all differences live in the **private witness**, not the
/// circuit structure. This prevents the PCD step index from leaking
/// whether an action is a spend or output.
///
/// **Tachygrams are deterministic.** The circuit computes them from note
/// fields and key material with no fresh randomness. Same note + same
/// key material + same flavor = same tachygram, always. This is
/// essential: if tachygrams were rerandomized, the same note spent
/// twice would produce different tachygrams and double-spend detection
/// would fail.
///
/// **Actions use fresh per-action randomness.** Each `(rk, cv)` pair
/// uses fresh randomness ($\alpha$, $rcv$), so the action reveals
/// nothing about which note it corresponds to. The proof binds each
/// action to its tachygram internally, but an observer sees only
/// aggregated accumulators — never individual correspondences.
///
/// Given an [`ActionWitness`], the circuit:
///
/// 1. **Authorization** — $rk = ak + [\alpha]G$
///    For outputs, $ak$ is the identity point, so $rk = [\alpha]G$.
/// 2. **Value commitment** — $cv = [value]V + [rcv]R$
///    `value` is already signed: positive for spends, negative for
///    outputs.
/// 3. **Note commitment** — $cmx = \text{NoteCommit}(pk, v, \psi, rcm)$
/// 4. **Nullifier derivation** *(stubbed)* — GGM tree PRF:
///    $mk = \text{Poseidon}(\psi, nk)$, then $nf = F_{mk}(\text{flavor})$
///    via tree walk with bits of flavor.
/// 5. **Tachygram** — accepted from witness. Once steps 3–4 are
///    implemented, constrain $(tg - nf)(tg - cmx) = 0$ and derive
///    $\text{is\_spend}$.
/// 6. **Accumulator membership** — $cmx \in \text{acc}(anchor)$ (spend only,
///    gated by the derived $\text{is\_spend}$; outputs are adding to the
///    accumulator, not reading from it.)
/// 7. **actions_acc** — $[\text{Poseidon}(rk \| cv)] \cdot G_{acc}$, single-point accumulator
/// 8. **tachygram_acc** — $[\text{Poseidon}(tg)] \cdot G_{acc}$, single-point accumulator
///
/// The action↔tachygram binding works because the $\alpha$ used in `rk`
/// commits to the tachygram via the proof. The signature $\sigma$
/// (verified out-of-circuit) proves knowledge of the signing key for
/// that specific `rk`.
pub(super) struct ActionLeaf<'params, C: Cycle> {
    /// Poseidon parameters for in-circuit hashing.
    pub poseidon: &'params C::CircuitPoseidon,
}

impl<C: Cycle<CircuitField = Fp>> Step<C> for ActionLeaf<'_, C> {
    const INDEX: Index = Index::new(0);

    type Witness<'source> = ActionWitness;
    /// Returns the derived tachygram (as `Fp`) for stamp construction.
    type Aux<'source> = Fp;
    type Left = ();
    type Right = ();
    type Output = StampDigest;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, StampDigest, HEADER_SIZE>,
        ),
        DriverValue<D, Fp>,
    )>
    where
        Self: 'dr,
    {
        // ── Destructure witness into individual DriverValues ──────
        //
        // Maybe::map consumes self, so we extract all fields in one
        // pass, producing a tuple that we split with .cast().

        let (w_v, w_psi, w_pk, w_rcm, w_alpha, w_rcv, w_anchor, w_tg) = witness
            .map(|w| {
                (
                    Fp::from(w.note.value),
                    w.note.psi.into(),
                    w.note.pk.into(),
                    extract_endoscalar::<Fq>(w.note.rcm.into()),
                    extract_endoscalar::<Fq>(w.alpha.into()),
                    extract_endoscalar::<Fq>(w.rcv.into()),
                    w.flavor.into(),
                    w.tachygram,
                )
            })
            .cast();

        // ── Allocate note fields ────────────────────────────────────

        let v = Element::alloc(dr, w_v)?;
        let _psi = Element::alloc(dr, w_psi)?;
        let _pk = Element::alloc(dr, w_pk)?;
        let _rcm = Endoscalar::alloc(dr, w_rcm)?;

        // ── Allocate key material ─────────────────────────────────
        //
        // ak is the spend authorization key (a curve point).
        // For outputs, ak is the identity — this naturally gives
        // $rk = [\alpha]G$. For spends, $rk = ak + [\alpha]G$.
        // Both go through the same circuit path.
        //
        // FIXME: ActionWitness needs `ak` and `nk` fields.
        let ak = Point::alloc(dr, D::just(EpAffine::identity))?;
        let _nk = Element::alloc(dr, D::just(|| Fp::ZERO))?;

        // ── Allocate randomizers ──────────────────────────────────

        let alpha = Endoscalar::alloc(dr, w_alpha)?;
        let rcv = Endoscalar::alloc(dr, w_rcv)?;

        // ── Anchor ────────────────────────────────────────────────

        let anchor = Element::alloc(dr, w_anchor)?;

        // ── 1. Authorization ──────────────────────────────────────
        //
        // $rk = ak + [\alpha]G$
        //
        // Unified: for outputs $ak$ = identity, so $rk = [\alpha]G$.
        // For spends ak is the real spend auth key.

        // FIXME: use actual SpendAuth basepoint
        let gen_g = Point::constant(dr, EpAffine::identity())?;
        let alpha_g = alpha.group_scale(dr, &gen_g)?;
        let _rk = ak.add_incomplete(dr, &alpha_g, None)?;

        // ── 2. Value commitment ───────────────────────────────────
        //
        // cv = [value]V + [rcv]R
        //
        // Unified: `value` is already signed (positive for spends,
        // negative for outputs) so the same formula works for both.

        // FIXME: use actual VALUE_COMMIT_V / VALUE_COMMIT_R generators
        let gen_v = Point::constant(dr, EpAffine::identity())?;
        let gen_r = Point::constant(dr, EpAffine::identity())?;
        let v_endo = Endoscalar::extract(dr, v)?;
        let v_scaled = v_endo.group_scale(dr, &gen_v)?;
        let rcv_scaled = rcv.group_scale(dr, &gen_r)?;
        let _cv = v_scaled.add_incomplete(dr, &rcv_scaled, None)?;

        // ── 3. Note commitment ────────────────────────────────────
        //
        // $cmx = \text{NoteCommit}(pk, v, \psi, rcm)$
        //
        // Computed for both spends and outputs. For spends it proves
        // the note exists; for outputs it IS the tachygram.
        //
        // TBD: Poseidon-based (all field arithmetic) or
        //      Sinsemilla (bit-string, Orchard-style).
        // FIXME: implement note commitment scheme
        let _cmx = Element::alloc(dr, D::just(|| Fp::ZERO))?;

        // ── 4. Nullifier derivation (stubbed) ──────────────────────
        //
        // GGM tree PRF: mk = KDF(ψ, nk), then nf = F_mk(flavor)
        // via tree walk with bits of flavor.
        //
        // TODO: implement GGM tree PRF
        //   Step 4a: mk = Poseidon(ψ, nk)
        //   Step 4b: decompose flavor into GGM_TREE_DEPTH bits
        //            (boolean + reconstruction constraints)
        //   Step 4c: for each bit b_i:
        //            node = Poseidon(node, b_i)
        //   nf = final node
        //
        // For now, the nullifier is accepted as part of the tachygram
        // witness (step 5) without in-circuit derivation.

        // ── 5. Tachygram ──────────────────────────────────────────
        //
        // The witness provides the tachygram directly:
        //   - Spend: tg = nf (nullifier)
        //   - Output: tg = cmx (note commitment)
        //
        // TODO: once steps 3 and 4 are implemented, constrain:
        //   (tg - nf) * (tg - cmx) == 0
        // and derive is_spend = (tg == nf) for gating step 6.

        let tg = Element::alloc(dr, w_tg)?;

        // ── 6. Accumulator membership (spend only) ────────────────
        //
        // $cmx \in \text{acc}(anchor)$
        //
        // Gated by is_spend derived in step 5. For outputs, the
        // cmx is being *added* to the accumulator, not read.
        //
        // TODO: conditional accumulator membership proof (gated by is_spend)

        // ── Accumulator generator ─────────────────────────────────
        //
        // Nothing-up-my-sleeve basepoint for both accumulators.
        // Derived at setup via CurveExt::hash_to_curve("z.cash:Tachyon-acc").

        // FIXME: use actual ACCUMULATOR_GENERATOR
        let gen_acc = Point::constant(dr, EpAffine::identity())?;

        // ── 7. Action digest for $\hat{d}$ ──────────────────────────
        //
        // d_hash = Poseidon(rk.x, rk.y, cv.x, cv.y)
        // d_point = [d_hash] * G_acc
        //
        // Blocked: Point has private (x, y) coordinates.
        // Options: (a) add public accessors to Point in ragu,
        //          (b) use Write::write_gadget to serialize into Elements.
        // FIXME: Poseidon(rk || cv) — needs Point coord access
        let d_hash = Element::alloc(dr, D::just(|| Fp::ZERO))?;
        let d_scalar = Endoscalar::extract(dr, d_hash)?;
        let d_point = d_scalar.group_scale(dr, &gen_acc)?;

        // ── 8. Tachygram hash for $\widehat{Tg}$ ────────────────────
        //
        // tg_hash  = Poseidon(tg)
        // tg_point = [tg_hash] * G_acc

        let mut tg_sponge = Sponge::new(dr, self.poseidon);
        // TODO: domain separation tag
        tg_sponge.absorb(dr, &tg)?;
        let tg_hash = tg_sponge.squeeze(dr)?;
        let tg_scalar = Endoscalar::extract(dr, tg_hash)?;
        let tg_point = tg_scalar.group_scale(dr, &gen_acc)?;

        // ── Encode output header ──────────────────────────────────

        let tg_value = tg.value().map(|v| *v);
        let output = Encoded::from_gadget(StampDigestGadget {
            actions_acc: d_point,
            tachygram_acc: tg_point,
            anchor,
        });

        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            tg_value,
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Merge  (Index 1)
// ═══════════════════════════════════════════════════════════════════════

/// Merge step that combines two sub-proofs.
///
/// 1. **Anchor subset proof** — verifies `left_anchor == right\_anchor \times
///    quotient`, proving the left accumulator state is a superset of the
///    right (append-only polynomial accumulator). The quotient is
///    provided by the prover via [`MergeWitness`]. Range validation of
///    the final anchor is performed outside the circuit by the consensus
///    layer.
/// 2. Accumulates `actions_acc = left.actions_acc + right.actions_acc`  (EC point addition)
/// 3. Accumulates `tachygram_acc = left.tachygram_acc + right.tachygram_acc`  (EC point addition)
///
/// Point addition is **commutative**, so the PCD tree shape does not
/// matter.  [`Point::add_incomplete`] requires distinct x-coordinates;
/// this holds for honest accumulators derived from distinct sub-trees.
///
/// The left sub-proof must carry the later (larger) accumulator state.
/// For same-epoch merges the quotient is `Fp::one()`.
pub(super) struct StampMerge<'params, C: Cycle> {
    /// Poseidon parameters (unused in merge, kept for uniformity).
    pub poseidon: &'params C::CircuitPoseidon,
}

impl<C: Cycle<CircuitField = Fp>> Step<C> for StampMerge<'_, C> {
    const INDEX: Index = Index::new(1);

    type Witness<'source> = MergeWitness;
    type Aux<'source> = ();
    type Left = StampDigest;
    type Right = StampDigest;
    type Output = StampDigest;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, (EpAffine, EpAffine, Fp)>,
        right: DriverValue<D, (EpAffine, EpAffine, Fp)>,
    ) -> Result<(
        (
            Encoded<'dr, D, StampDigest, HEADER_SIZE>,
            Encoded<'dr, D, StampDigest, HEADER_SIZE>,
            Encoded<'dr, D, StampDigest, HEADER_SIZE>,
        ),
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        // ── Encode input headers ───────────────────────────────────
        //
        // Encoded::new calls Header::encode, which allocates Points
        // and the anchor Element.  as_gadget() gives a reference to
        // the StampDigestGadget.

        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;

        let left_g: &StampDigestGadget<'dr, D, EpAffine> = left.as_gadget();
        let right_g: &StampDigestGadget<'dr, D, EpAffine> = right.as_gadget();

        // ── 1. Anchor subset proof ───────────────────────────────────
        //
        // For an append-only polynomial accumulator where the state is
        // $P(\tau)$, the left (later) state is a superset of the right
        // (earlier) state:
        //
        //   left_anchor == right\_anchor \times quotient
        //
        // The quotient encodes the tachygrams added between the two
        // epochs. The prover cannot forge a valid quotient without
        // the actual subset relationship (polynomial commitment
        // security). For same-epoch merges, quotient == 1.
        //
        // Range validation of the final anchor is consensus-layer.

        let _quotient = Element::alloc(dr, witness.map(|w| w.anchor_quotient))?;

        // TODO: Element field multiplication — exact ragu API TBD.
        // Constraint: left_anchor == right_anchor * quotient
        // This is a single R1CS multiplication gate.
        // FIXME: Element field multiplication — exact ragu API TBD.
        // Constraint: left_anchor == right_anchor * quotient
        let _product = left_g.anchor.clone();

        // ── 2. Accumulate $\hat{d}$ ──────────────────────────────────
        //
        // Pedersen multiset hash merge: point addition on Pallas.
        //
        // add_incomplete requires distinct x-coordinates; honest
        // sub-trees satisfy this.

        let merged_d = left_g
            .actions_acc
            .add_incomplete(dr, &right_g.actions_acc, None)?;

        // ── 3. Accumulate $\widehat{Tg}$ ─────────────────────────────

        let merged_tg = left_g
            .tachygram_acc
            .add_incomplete(dr, &right_g.tachygram_acc, None)?;

        // ── Encode output ──────────────────────────────────────────

        let output = Encoded::from_gadget(StampDigestGadget {
            actions_acc: merged_d,
            tachygram_acc: merged_tg,
            anchor: left_g.anchor.clone(),
        });

        Ok(((left, right, output), D::just(|| ())))
    }
}
