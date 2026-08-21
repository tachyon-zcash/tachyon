//! The covering read: two committed polynomials agree on a coefficient
//! window, given a sentineled free polynomial above the window and a
//! cap-shifted sentineled free polynomial below it.
//!
//! For a read of `members` consecutive coefficients out of a covering
//! polynomial `g`, with `margin` coefficients of `g` below the window and the
//! rest above it, the decomposition
//! `g = X^{members+margin}·older + X^margin·read + newer` is multiplied
//! through by `X^{CAP−margin}`, lifting the read window to degrees
//! `[CAP, CAP+members)`. Pedersen commitments bound degree from above only,
//! so `newer` is unconstrained where it sits; the lift is what confines it:
//!
//! ```text
//! z^{CAP−margin}·g(z) = z^{CAP+members}·(older(z) − 1)
//!     + z^CAP·read(z) + (tail(z) − 1)
//! ```
//!
//! with honest witnesses `older + 1` and `tail = X^{CAP−margin}·newer + 1`
//! (the `−1` terms compensate the sentinels that keep empty margins off the
//! identity point). The physical cap is the degree bound and the challenge
//! point is what applies it: a witnessed polynomial holds at most [`CAP`]
//! coefficients, so `tail` cannot reach the read's band and no
//! prover-controlled term perturbs the read. The bands are disjoint —
//! `older` lands at `[CAP+members, ·)`, the read at `[CAP, CAP+members)`,
//! `tail` under `CAP` — so the point-wise identity at a random `z` forces the
//! read's coefficients onto `g`'s exactly (Schwartz-Zippel), forces `tail`'s
//! coefficients under `CAP−margin` to zero with its sentinel slot exactly 1,
//! and says nothing about the margins' member values, which absorb whatever
//! `g` genuinely carries there.
//!
//! The relation requires `g`'s rank to be exactly `members + margin` plus the
//! older margin, which is what places the bands. Callers pin the rank through
//! an announced span and a nonzero top coefficient; the module-level binding
//! obligation of [`super::enforce`] applies to every committed operand.

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Error, Result, ctx::StepCtx, polynomial::Polynomial};

/// The physical coefficient cap witnessed polynomials cannot exceed, from
/// [`Polynomial::R`]. The soundness argument rests on this being *the*
/// witnessability cap.
pub(crate) const CAP: u64 = 1 << Polynomial::R;

/// Confirm a committed polynomial `read` matches `members` consecutive
/// coefficients of the committed covering polynomial `g`, `margin`
/// coefficients above `g`'s degree 0.
///
/// Derives the challenge internally over all four commitments. No witness is
/// built from it, so a transcript challenge serves.
///
/// # Caller obligations (soundness)
///
/// The module-level binding obligation for `g` and `read`; `older` and
/// `tail` are absorbing witnesses and need no external pin. `margin` and
/// `members` must be statement-fixed (header values), and `g`'s rank pinned
/// as the module documents.
#[expect(
    clippy::too_many_arguments,
    reason = "the four polynomials and the window bounds are all independent \
              statement inputs"
)]
pub(crate) fn enforce_covering_read(
    ctx: &mut StepCtx<'_>,
    g: &Polynomial,
    older: &Polynomial,
    tail: &Polynomial,
    read: &Polynomial,
    members: u64,
    margin: u64,
    err: &'static str,
) -> Result<()> {
    let g_com = g.commit();
    let older_com = older.commit();
    let tail_com = tail.commit();
    let read_com = read.commit();
    let z = ctx.derive_challenge(&[g_com, older_com, tail_com, read_com])?;

    check_read_identity(g, older, tail, read.eval(z), members, margin, z, err)?;

    ctx.enforce_poly_query(g_com, z, g.eval(z))?;
    ctx.enforce_poly_query(older_com, z, older.eval(z))?;
    ctx.enforce_poly_query(tail_com, z, tail.eval(z))?;
    ctx.enforce_poly_query(read_com, z, read.eval(z))?;

    Ok(())
}

/// Confirm the scalars `members` match consecutive coefficients of the
/// committed covering polynomial `g`, `margin` coefficients above `g`'s
/// degree 0, at the caller-supplied challenge `z`.
///
/// The members enter as monomial coefficients, so they carry no commitment,
/// and the identity is linear in each. **The caller must derive `z` over the
/// three commitments and every member** (see `poseidon::read_challenge`),
/// which makes the solve a fixed point and forces each member to `g`'s
/// genuine coefficient.
///
/// # Caller obligations (soundness)
///
/// The `z` derivation above; the module-level binding obligation for `g`;
/// statement-fixed `margin`; `g`'s rank pinned as the module documents.
#[expect(
    clippy::too_many_arguments,
    reason = "the polynomials, members, and window bounds are all independent \
              statement inputs"
)]
pub(crate) fn enforce_covering_read_members<const MEMBERS: usize>(
    ctx: &mut StepCtx<'_>,
    g: &Polynomial,
    older: &Polynomial,
    tail: &Polynomial,
    members: [Fp; MEMBERS],
    margin: u64,
    z: Fp,
    err: &'static str,
) -> Result<()> {
    let read_at_z = members
        .iter()
        .fold(Fp::ZERO, |acc, &member| acc * z + member);

    #[expect(clippy::as_conversions, reason = "member counts are tiny constants")]
    check_read_identity(g, older, tail, read_at_z, MEMBERS as u64, margin, z, err)?;

    ctx.enforce_poly_query(g.commit(), z, g.eval(z))?;
    ctx.enforce_poly_query(older.commit(), z, older.eval(z))?;
    ctx.enforce_poly_query(tail.commit(), z, tail.eval(z))?;

    Ok(())
}

/// The lifted identity at `z`. Every exponent is bounded by the rank cap.
#[expect(
    clippy::too_many_arguments,
    reason = "the identity's operands and window bounds are all inputs"
)]
fn check_read_identity(
    g: &Polynomial,
    older: &Polynomial,
    tail: &Polynomial,
    read_at_z: Fp,
    members: u64,
    margin: u64,
    z: Fp,
    err: &'static str,
) -> Result<()> {
    let z_cap = z.pow_vartime([CAP]);
    let lhs = z.pow_vartime([CAP - margin]) * g.eval(z);
    let rhs = z_cap * z.pow_vartime([members]) * (older.eval(z) - Fp::ONE)
        + z_cap * read_at_z
        + (tail.eval(z) - Fp::ONE);
    if lhs != rhs {
        return Err(Error::InvalidWitness(err.into()));
    }
    Ok(())
}
