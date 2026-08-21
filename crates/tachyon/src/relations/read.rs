//! The covering read: two committed polynomials agree on a coefficient
//! window, given a sentineled free polynomial above the window and a
//! cap-shifted sentineled free polynomial below it.
//!
//! For a read of `members` consecutive coefficients out of a covering
//! polynomial `g`, with `margin` coefficients of `g` below the window and the
//! rest above it, the naive decomposition
//! `g = X^{members+margin}·above + X^margin·read + below` is never checked
//! directly: Pedersen commitments bound degree from above only, so a free
//! polynomial below the read is vacuous. Instead the whole identity is
//! multiplied through by `X^{CAP−margin}`, lifting the read window to degrees
//! `[CAP, CAP+members)`:
//!
//! ```text
//! z^{CAP−margin}·g(z) = z^{CAP+members}·(older(z) − 1)
//!     + z^CAP·read(z) + (tail(z) − 1)
//! ```
//!
//! with honest witnesses `older = above + 1` and
//! `tail = X^{CAP−margin}·below + 1` (the `−1` terms compensate the
//! sentinels that keep empty margins off the identity point; `above` carries
//! `g`'s own sentinel as its top coefficient, so it is never empty). The
//! physical cap is the degree bound and the challenge point is what applies
//! it: a witnessed polynomial holds at most [`CAP`] coefficients, so `tail`
//! cannot reach the read's band and no prover-controlled term perturbs the
//! read. The bands are disjoint — `older` lands at `[CAP+members, ·)`, the
//! read at `[CAP, CAP+members)`, `tail` under `CAP` — so the point-wise
//! identity at a random `z` forces the read's coefficients onto `g`'s exactly
//! (Schwartz-Zippel), forces `tail`'s coefficients under `CAP−margin` to zero
//! with its sentinel slot exactly 1, and says nothing about the margins'
//! member values, which absorb whatever `g` genuinely carries there.
//!
//! The relation assumes `g`'s rank is exactly its announced span plus its
//! sentinel: a rank-short `g` slides every band. The sequence sentinel
//! ([`NfSeqPoly`](crate::primitives::NfSeqPoly)) provides the pin — the
//! derivation's accumulation opening forces the top coefficient to exactly
//! $1$ at the announced span. The module-level binding obligation of
//! [`super::enforce`] applies to every committed operand.

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Error, Result, ctx::StepCtx, polynomial::Polynomial};

/// The physical coefficient cap witnessed polynomials cannot exceed.
pub(crate) const CAP: u64 = 1 << Polynomial::R;

/// Confirm a committed sentinel-terminated polynomial `read`, its sentinel
/// swapped for the statement-fixed scalar `cap_member`, matches
/// `read_members + 1` consecutive coefficients of the committed covering
/// polynomial `g`, `margin` coefficients above `g`'s degree 0.
///
/// The read band is `read`'s members followed by `cap_member`: the swap
/// contributes `(cap_member − 1)·z^read_members` to the read evaluation,
/// challenge-independent because both `cap_member` and `read_members` are
/// statement-fixed.
///
/// Derives the challenge internally over all four commitments; no witness is
/// built from it, so it is a free transcript challenge.
///
/// # Caller obligations (soundness)
///
/// The module-level binding obligation for `g` and `read`; `older` and
/// `tail` are absorbing witnesses and need no external pin. `margin`,
/// `read_members`, and `cap_member` must be statement-fixed (header values),
/// and `g`'s rank pinned as the module documents.
#[expect(
    clippy::too_many_arguments,
    reason = "a covering read names its four polynomials and its window arithmetic"
)]
pub(crate) fn enforce_covering_read(
    ctx: &mut StepCtx<'_>,
    g: &Polynomial,
    older: &Polynomial,
    tail: &Polynomial,
    read: &Polynomial,
    cap_member: Fp,
    read_members: u64,
    margin: u64,
    err: &'static str,
) -> Result<()> {
    let g_com = g.commit();
    let older_com = older.commit();
    let tail_com = tail.commit();
    let read_com = read.commit();
    let z = ctx.derive_challenge(&[g_com, older_com, tail_com, read_com])?;

    let read_at_z = read.eval(z) + (cap_member - Fp::ONE) * z.pow_vartime([read_members]);
    check_read_identity(g, older, tail, read_at_z, read_members + 1, margin, z, err)?;

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
/// `members` are given newest-first: the first entry takes the band's top
/// degree and the last its degree 0, matching the covering sequence's
/// ascending order.
///
/// # Caller obligations (soundness)
///
/// **`z` must be derived over the three commitments and every member** (see
/// [`read_challenge`](crate::digest::poseidon::read_challenge)): the identity
/// is linear in each member, so one chosen after `z` is known is solvable
/// against garbage margins. Also the module-level binding obligation for `g`,
/// statement-fixed `margin`, and `g`'s rank pinned as the module documents.
#[expect(
    clippy::too_many_arguments,
    reason = "a covering read names its polynomials, members, and window arithmetic"
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

/// The lifted identity at `z`. The runtime exponents are native mock
/// stand-ins for fixed-width exponentiation chains.
#[expect(clippy::too_many_arguments, reason = "one identity, named operands")]
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
