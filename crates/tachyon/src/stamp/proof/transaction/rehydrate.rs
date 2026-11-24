//! Confirming a portable wallet bridge against a local aggregator bridge.

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use ragu::{
    Coeff, Cycle as _, Error, FixedGenerators as _, Polynomial, Rank, Result, WalletRank,
    circuits::polynomials,
    drivers::{Driver, DriverValue, LinearExpression as _},
    header::Header,
    maybe::Maybe as _,
    pasta::{EpAffine, EqAffine, Fp, Fq, Pasta, PastaParams},
    pcd::{bridge_hash, ipa::IpaCycle as _, pasta as parameters, profile},
    primitives::{Boolean, Element, FixedBase, GadgetExt as _, Point, vec::FixedVec},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::{
        curve::{Affine as _, Projective as _},
        field::Field as _,
    },
};

use super::{PublicTransaction, Transaction, TransactionOutput};
use crate::{ActionSetBridge, ActionSetCommit, ActionSetPoly};

/// The coordinate degrees and the single active gate of a pinned bridge stage.
struct Layout {
    x: usize,
    y: usize,
    gate: usize,
    n: usize,
}

impl Layout {
    #[expect(
        clippy::expect_used,
        reason = "invariants of the fixed baked setup, never proof inputs"
    )]
    fn pinned<R: Rank>(
        probe: EqAffine,
        stage: &Polynomial<Fq, R>,
        expected: (usize, usize),
    ) -> Self {
        let (x, y) = probe
            .coordinates()
            .filter(|&(x, y)| x != y)
            .expect("fixed probe has distinguishable finite coordinates");
        let mut terms = stage
            .iter_stored_coeffs()
            .filter(|&(_, coefficient)| *coefficient != Fq::ZERO);
        let (even, &first) = terms.next().expect("bridge stage has an x term");
        let (odd, &second) = terms.next().expect("bridge stage has a y term");
        assert!(
            terms.next().is_none(),
            "unexpected extra bridge coefficient"
        );
        assert_eq!((even, odd), expected, "pinned bridge degrees changed");
        assert_eq!(
            (first, second),
            (x, y),
            "bridge coordinates in unexpected order"
        );
        let n = R::n();
        assert!(
            (n..2 * n).contains(&even) && odd == even + 2 * n,
            "bridge terms must occupy the a,d wires of one gate"
        );
        let gate = 2 * n - 1 - even;
        assert!(
            gate > 0 && gate < R::blind_gate(),
            "bridge uses a reserved gate"
        );
        Self {
            x: even,
            y: odd,
            gate,
            n,
        }
    }

    const fn permits(&self, degree: usize) -> bool {
        let n = self.n;
        if degree >= 4 * n {
            return false;
        }
        // Trace columns in degree order: c, reversed a, b, reversed d.
        let offset = degree & (n - 1);
        let gate = if degree & n == 0 {
            offset
        } else {
            n - 1 - offset
        };
        gate == 0 || gate == self.gate || gate == n - 1
    }

    #[expect(
        clippy::expect_used,
        reason = "the baked stage supplement must cover the pinned degrees"
    )]
    fn generators(&self, params: &PastaParams, opposite: &Self) -> [EpAffine; 2] {
        [self.x, self.y].map(|index| {
            assert!(
                !opposite.permits(index),
                "bridge coordinate degree allowed by opposite stage mask"
            );
            let point =
                Pasta::nested_generator(params, index).expect("missing baked bridge generator");
            assert!(!point.is_identity(), "identity bridge generator");
            if index < WalletRank::num_coeffs() {
                assert_eq!(
                    Some(&point),
                    Pasta::nested_generators(params).g().get(index),
                    "wallet generator disagrees with the baked prefix"
                );
            }
            point
        })
    }
}

/// Restores the working action polynomial from a [`PublicTransaction`].
///
/// Both applications register this circuit at 40 with the same difference
/// tables. Registration does not prove that the caller is an aggregator.
/// The issuer's wallet padding check establishes the input bridge's basis;
/// import preserves that statement. The cross-rank relation excludes a
/// same-basis restore without repeating the padding check here.
///
/// The input anchor is copied. The prepared last slot is explicitly opened
/// at ζ to keep it live. Its **own** bridge, not that opening's value, ties
/// the candidate to the published action binding. The working header reports
/// the exact oracle coordinates, not a separately witnessed digest.
/// With the width-nine step adapter, step 40 uses 1,405 gates and 2,828
/// linear constraints (wallet limits: 2,047 and 8,191). Rank changes the
/// available capacity, not the constraints emitted here.
#[derive(Clone, Debug)]
pub struct TransactionRehydrate {
    x: FixedBase<EpAffine, 255>,
    y: FixedBase<EpAffine, 255>,
}

impl TransactionRehydrate {
    /// Prepare the *same* two constants for both applications, using their
    /// common Pasta setup. The probe labels `rx`'s two terms for one known
    /// point; it does not prove the layout for every point. This relies on
    /// the pinned Ragu bridge stage staging exactly two coordinates in
    /// **one** gate and using the ordinary stage mask. Check those upstream
    /// contracts on upgrades: `rx` exposes the honest coefficients, not the
    /// registered mask of Ragu's private nested bridge stage. Compare `permits`
    /// with that stage's registered `StageExt::mask` at both opposite degrees
    /// when changing the pin. Conservatively allow every wire of SYSTEM,
    /// the active gate and the blind gate, and reject either layout
    /// allowing the other rank's x or y degree.
    ///
    /// # Errors
    /// Propagates stage and fixed-base construction errors from Ragu.
    ///
    /// # Panics
    /// If the compiled stage layout or baked generators violate the pinned
    /// invariants. No rank, index, parameter or table comes from the prover.
    #[expect(
        clippy::expect_used,
        reason = "compiled generator tables must cover both pinned bridge stages"
    )]
    pub fn new() -> Result<Self> {
        let params = parameters::baked();
        let probe = *Pasta::host_generators(params)
            .g()
            .first()
            .expect("baked host generators include a probe");
        let wallet = Layout::pinned(
            probe,
            &bridge_hash::rx::<_, WalletRank>(probe)?,
            (3975, 8071),
        );
        let aggregator = Layout::pinned(
            probe,
            &bridge_hash::rx::<_, polynomials::AggregatorRank>(probe)?,
            (16263, 32647),
        );
        let [wx, wy] = wallet.generators(params, &aggregator);
        let [gx, gy] = aggregator.generators(params, &wallet);
        let difference = |portable: EpAffine, local: EpAffine| {
            FixedBase::new(
                (portable.to_projective() - local.to_projective()).to_affine(),
                EpAffine::identity(),
            )
        };
        Ok(Self {
            x: difference(wx, gx)?,
            y: difference(wy, gy)?,
        })
    }

    /// Enforce `portable = local + u·(Wx−Gx) + v·(Wy−Gy)`. The inputs must
    /// come from authenticated bridges, not just allocated points: in
    /// rehydration `portable` comes from the input header and `local` from
    /// the step's own output-slot oracle. The points do not identify their
    /// setup, rank, or provenance. This does not itself open a polynomial.
    ///
    /// Subtract the certified stage coefficient vectors in the common nested
    /// generator basis. Under commitment binding the difference has `u,v` at
    /// the wallet degrees, `−u,−v` at the aggregator degrees, zero elsewhere.
    /// Each opposite mask excludes the two degrees, so reading those entries
    /// gives the same coordinates in both stages. Common extra terms can
    /// cancel: neither stage is required to be canonical, and not every
    /// noncanonical pair can be converted. In particular, this is an **import
    /// check**, not a way to produce a canonical portable point from an
    /// arbitrary local digest. The bits act modulo the Pallas group order
    /// (the Vesta base field); no canonical integer encoding is asserted.
    ///
    /// For two stages of the same rank both coordinate degrees of the other
    /// rank are absent, forcing `u=v=0` as residues and hence equal endpoints.
    /// The separate endpoint disequality rejects this, even for noncanonical
    /// bit representatives of zero. No affine point difference is allocated.
    ///
    /// # Errors
    /// Affine arithmetic excludes identities and opposite intermediate addends.
    /// Such cases can prevent witness generation; they do not provide another
    /// opening. A checking driver rejects unequal final points.
    fn enforce_same_coordinates<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        portable: [&Element<'dr, D>; 2],
        oracle: [&Element<'dr, D>; 2],
        coordinates: DriverValue<D, [Fq; 2]>,
    ) -> Result<Point<'dr, D, EpAffine>> {
        // Reject an unrepresentable portable witness before doing arithmetic.
        // The final bind below constrains its two wires to the computed point.
        D::try_just(|| {
            EpAffine::from_xy(*portable[0].value().take(), *portable[1].value().take())
                .map(|_| ())
                .ok_or_else(|| Error::InvalidWitness("invalid action bridge".into()))
        })?;
        let [ox, oy] = oracle;
        let local = Point::alloc(
            dr,
            D::try_just(|| {
                EpAffine::from_xy(*ox.value().take(), *oy.value().take())
                    .ok_or_else(|| Error::InvalidWitness("invalid action bridge".into()))
            })?,
        )?;
        bind(dr, &local, oracle)?;
        let delta = [portable[0].sub(dr, ox), portable[1].sub(dr, oy)];
        // Free B wires: choose an inverse on either nonzero axis. When both
        // differences vanish no choices can satisfy the final equation.
        let multipliers = D::just(|| {
            delta[0].value().take().invert().map_or_else(
                || {
                    [
                        Fp::ZERO,
                        delta[1].value().take().invert().unwrap_or(Fp::ZERO),
                    ]
                },
                |inverse| [inverse, Fp::ZERO],
            )
        });
        let mut product = |difference: &Element<'dr, D>, scalar: DriverValue<D, Fp>| {
            let (input, _, output) = dr.mul(|| {
                let value = *difference.value().take();
                let factor = *scalar.as_ref().take();
                Ok((
                    Coeff::Arbitrary(value),
                    Coeff::Arbitrary(factor),
                    Coeff::Arbitrary(value * factor),
                ))
            })?;
            dr.enforce_equal(&input, difference.wire())?;
            Ok::<_, Error>(output)
        };
        let first = product(&delta[0], multipliers.as_ref().map(|values| values[0]))?;
        let second = product(&delta[1], multipliers.map(|values| values[1]))?;
        dr.enforce_zero(|lc| lc.add(&first).add(&second).sub(&D::ONE))?;
        let mut bits = |coordinate: DriverValue<D, Fq>| {
            let encoding = coordinate.map(|value| value.to_le_bits());
            FixedVec::try_from_fn(|index| {
                Boolean::alloc(
                    dr,
                    &mut (),
                    encoding
                        .as_ref()
                        .map(|digits| digits.as_ref().get(index).is_some_and(|bit| *bit)),
                )
            })
        };
        let x = bits(coordinates.as_ref().map(|&[x, _]| x))?;
        let y = bits(coordinates.map(|[_, y]| y))?;
        let partial = self.x.mul_and_add(dr, &x, &local)?;
        let computed = self.y.mul_and_add(dr, &y, &partial)?;
        bind(dr, &computed, portable)?;
        Ok(local)
    }

    fn restore<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        public: &TransactionOutput<'dr, D>,
        oracle: [&Element<'dr, D>; 2],
        commitment: DriverValue<D, EqAffine>,
    ) -> Result<(TransactionOutput<'dr, D>, DriverValue<D, ActionSetBridge>)> {
        let coordinates = D::try_just(|| {
            commitment
                .take()
                .coordinates()
                .map(Into::into)
                .ok_or_else(|| Error::InvalidWitness("identity action commitment".into()))
        })?;
        let local = self.enforce_same_coordinates(
            dr,
            public.action_set_bridge.each_ref(),
            oracle,
            coordinates,
        )?;
        Ok((
            TransactionOutput {
                anchor: public.anchor.clone(),
                action_set_bridge: oracle.map(Clone::clone),
            },
            local.value().map(ActionSetBridge::from),
        ))
    }
}

fn bind<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    point: &Point<'dr, D, EpAffine>,
    coordinates: [&Element<'dr, D>; 2],
) -> Result<()> {
    let mut wires = Vec::new();
    point.write(dr, &mut wires)?;
    for (actual, expected) in wires.iter().zip(coordinates) {
        actual.enforce_equal(dr, expected)?;
    }
    Ok(())
}

impl<C: profile::ProfiledCycle<Base = Pasta, CircuitField = Fp>> Step<C> for TransactionRehydrate {
    type Aux<'source> = ();
    type Left = PublicTransaction;
    type Output = Transaction;
    type Right = ();
    /// Candidate coefficients in ascending degree and the commitment to open.
    /// Ragu checks the slot's rank bound before commitment. The witness point
    /// is not trusted: its coordinate residues must satisfy the conversion.
    type Witness<'source> = (ActionSetPoly, ActionSetCommit);

    const INDEX: Index = Index::new(40);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<Prepared<Fp, Self::Output>> {
        Ok(ActionSetPoly::SLOT.poly(Prepared::new(), &witness.0))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let input = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let unit = Encoded::new(dr, &mut (), right)?;
        let zeta = oracles.zeta().clone();
        let _opening = oracles.output(ActionSetPoly::SLOT).open(dr, &zeta)?;
        let oracle = oracles.bridge_hash();
        let (fields, bridge) = self.restore(
            dr,
            input.as_gadget(),
            [oracle.x(), oracle.y()],
            witness.map(|candidate| EqAffine::from(candidate.1)),
        )?;
        let data = D::just(|| (bridge.take(), left.take().1));
        Ok(((input, unit, Encoded::from_gadget(fields)), data, D::unit()))
    }
}
