//! A wallet-rank bridge hash from a step's own bridge hash at either rank.
//!
//! Ragu places a commitment's two coordinates at rank-dependent degrees of
//! the bridge stage and commits that stage under one shared nested generator
//! table. The canonical wallet and aggregator bridge hashes of one commitment
//! $(x, y)$ therefore differ by $x \cdot D_1 + y \cdot D_2$, where
//! $D_1 = W_1 - G_1$ and $D_2 = W_2 - G_2$ are the differences of the
//! generators at the wallet and aggregator coordinate degrees.

use alloc::{format, vec::Vec};

use lazy_static::lazy_static;
use ragu::{
    Cycle as _, Error, FixedGenerators as _, Polynomial, Rank, Result, WalletRank,
    circuits::{
        polynomials::AggregatorRank,
        registry::{CircuitIndex, RegistryBuilder},
        staging::{stage_gates, stage_mask},
    },
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
    pasta::{EpAffine, EqAffine, Fp, Fq, Pasta},
    pcd::{bridge_hash, ipa::IpaCycle as _, pasta as parameters},
    primitives::{Boolean, Element, FixedBase, GadgetExt as _, Point, vec::FixedVec},
    udon::{
        curve::{Affine as _, Projective as _},
        field::Field as _,
    },
};
use ragu_pcd::pasta::baked_aggregator;

lazy_static! {
    /// The generator differences of the pinned wallet and aggregator bridge
    /// stages, shared by both applications.
    ///
    /// Setup checks the pinned stage layout of each rank, that each rank's
    /// registered stage mask holds the other rank's coordinate degrees to
    /// zero, and that the wallet and aggregator tables agree at all four
    /// degrees, so a Ragu re-pin that changes any of these fails here.
    pub(crate) static ref CONVERSION: BridgeConversion = {
        let build = || -> Result<BridgeConversion> {
            let wallet_table = parameters::baked();
            let aggregator_table = baked_aggregator();
            let probe = *Pasta::host_generators(wallet_table)
                .g()
                .first()
                .ok_or_else(|| Error::Initialization("no baked host generator".into()))?;
            let wallet = Layout::pinned(
                probe,
                &bridge_hash::rx::<_, WalletRank>(probe)?,
                [3975, 8071],
            )?;
            let aggregator = Layout::pinned(
                probe,
                &bridge_hash::rx::<_, AggregatorRank>(probe)?,
                [16263, 32647],
            )?;
            wallet.excludes::<WalletRank>(aggregator.degrees)?;
            aggregator.excludes::<AggregatorRank>(wallet.degrees)?;
            let generator = |index: usize| {
                let point = Pasta::nested_generators(aggregator_table)
                    .g()
                    .get(index)
                    .copied()
                    .filter(|point| !point.is_identity())
                    .ok_or_else(|| Error::Initialization("missing bridge generator".into()))?;
                let shared = Pasta::nested_generators(wallet_table)
                    .g()
                    .get(index)
                    .map_or_else(
                        || Pasta::nested_generator(wallet_table, index) == Some(point),
                        |wallet_point| *wallet_point == point,
                    );
                if shared {
                    Ok(point)
                } else {
                    Err(Error::Initialization(
                        "wallet and aggregator bridge generators differ".into(),
                    ))
                }
            };
            let difference = |wallet_degree: usize, aggregator_degree: usize| {
                FixedBase::new(
                    (generator(wallet_degree)?.to_projective()
                        - generator(aggregator_degree)?.to_projective())
                    .to_affine(),
                    EpAffine::identity(),
                )
            };
            Ok(BridgeConversion {
                x: difference(wallet.degrees[0], aggregator.degrees[0])?,
                y: difference(wallet.degrees[1], aggregator.degrees[1])?,
            })
        };
        #[expect(
            clippy::expect_used,
            reason = "the pinned Ragu bridge stages and baked generators are fixed setup, never proof inputs"
        )]
        let conversion = build().expect("pinned bridge stage layouts");
        conversion
    };
}

/// The two coordinate degrees and the gate of a pinned bridge stage.
struct Layout {
    degrees: [usize; 2],
    gate: usize,
}

impl Layout {
    /// Reads the two nonzero degrees of `stage`, the canonical bridge stage of
    /// `probe`, and checks them against the pin.
    fn pinned<R: Rank>(
        probe: EqAffine,
        stage: &Polynomial<Fq, R>,
        expected: [usize; 2],
    ) -> Result<Self> {
        let invalid = |reason: &'static str| Error::Initialization(reason.into());
        let (x, y) = probe
            .coordinates()
            .filter(|&(x, y)| x != y)
            .ok_or_else(|| invalid("probe coordinates must be finite and distinct"))?;
        let terms: Vec<_> = stage
            .iter_stored_coeffs()
            .filter(|&(_, coefficient)| *coefficient != Fq::ZERO)
            .collect();
        let &[(even, &first), (odd, &second)] = terms.as_slice() else {
            return Err(invalid("bridge stage must hold exactly two terms"));
        };
        if [even, odd] != expected {
            return Err(invalid("pinned bridge degrees changed"));
        }
        if (first, second) != (x, y) {
            return Err(invalid("bridge coordinates in unexpected order"));
        }
        let n = R::n();
        if !(n..2 * n).contains(&even) || odd != even + 2 * n {
            return Err(invalid(
                "bridge terms must occupy the a,d wires of one gate",
            ));
        }
        Ok(Self {
            degrees: expected,
            gate: 2 * n - 1 - even,
        })
    }

    /// Checks that Ragu's mask for a two-value stage at this gate holds the
    /// `opposite` degrees to zero and leaves this stage's own degrees free.
    ///
    /// Ragu registers the bridge stage under its ordinary stage mask, which
    /// is [`stage_mask`] of the stage's gate and size. A degree beyond the
    /// rank's coefficients cannot be committed at that rank at all.
    fn excludes<R: Rank>(&self, opposite: [usize; 2]) -> Result<()> {
        let registry = RegistryBuilder::<Fq, R>::new()
            .register_mask(stage_mask::<R>(self.gate, stage_gates(2))?)
            .finalize()?;
        // The mask is a wiring polynomial, the coefficient reversal of the
        // trace it constrains: restricted to `y`, it holds trace degree `k` to
        // zero exactly when its coefficient at `num_coeffs - 1 - k` is nonzero.
        let mask = registry.circuit_y(CircuitIndex::new(0), Fq::ONE);
        let held = |degree: usize| {
            let wiring = R::num_coeffs() - 1 - degree;
            mask.iter_stored_coeffs()
                .any(|(at, coefficient)| at == wiring && *coefficient != Fq::ZERO)
        };
        if self.degrees.into_iter().any(held) {
            return Err(Error::Initialization(
                "bridge stage mask holds its own coordinate degree".into(),
            ));
        }
        if opposite
            .into_iter()
            .any(|degree| degree < R::num_coeffs() && !held(degree))
        {
            return Err(Error::Initialization(
                "bridge stage mask admits the other rank's coordinate degree".into(),
            ));
        }
        Ok(())
    }
}

/// Fixed differences of the wallet and aggregator bridge generators, for the
/// x and y coordinates.
pub(crate) struct BridgeConversion {
    x: FixedBase<EpAffine, 255>,
    y: FixedBase<EpAffine, 255>,
}

impl BridgeConversion {
    /// Returns the coordinates of `own + u·D₁ + v·D₂` for witnessed 255-bit
    /// `u` and `v`, where `own` is the executing step's output oracle.
    ///
    /// Witness generation takes `u` and `v` as the coordinates of
    /// `commitment` when `own` is not already `wallet`, the commitment's
    /// canonical wallet-rank bridge hash, and zero when it is.
    ///
    /// # Soundness
    ///
    /// The result is any point of `own + ⟨D₁, D₂⟩`; nothing here makes it a
    /// bridge hash. The bits act modulo the Pallas group order, with no
    /// canonical integer encoding asserted. [`AnchorSpanSeed`] gives the
    /// argument that equating the result with a canonical wallet bridge hash
    /// makes `own` canonical.
    ///
    /// [`AnchorSpanSeed`]: crate::stamp::proof::pool::AnchorSpanSeed#soundness
    ///
    /// # Errors
    /// Returns a witness error if `own` is not a finite Pallas point. Affine
    /// arithmetic rejects an opposite prefix or addend and an identity sum
    /// during witness generation.
    pub(crate) fn wallet_bridge<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        own: [&Element<'dr, D>; 2],
        commitment: DriverValue<D, (EqAffine, EpAffine)>,
    ) -> Result<[Element<'dr, D>; 2]> {
        let [own_x, own_y] = own;
        let start = D::try_just(|| {
            EpAffine::from_xy(*own_x.value().take(), *own_y.value().take())
                .ok_or_else(|| Error::InvalidWitness("invalid bridge hash".into()))
        })?;
        let scalars = D::try_just(|| {
            let (point, wallet) = commitment.take();
            if wallet == *start.as_ref().take() {
                return Ok([Fq::ZERO; 2]);
            }
            point
                .coordinates()
                .map(<[Fq; 2]>::from)
                .ok_or_else(|| Error::InvalidWitness("identity commitment".into()))
        })?;
        let local = Point::alloc(dr, start)?;
        let mut wires = Vec::new();
        local.write(dr, &mut wires)?;
        for (actual, expected) in wires.iter().zip(own) {
            actual.enforce_equal(dr, expected)?;
        }
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
        let x_bits = bits(scalars.as_ref().map(|scalar| scalar[0]))?;
        let y_bits = bits(scalars.map(|scalar| scalar[1]))?;
        let partial = self.x.mul_and_add(dr, &x_bits, &local)?;
        let mut sum = Vec::new();
        self.y
            .mul_and_add(dr, &y_bits, &partial)?
            .write(dr, &mut sum)?;
        <[Element<'dr, D>; 2]>::try_from(sum).map_err(|written| {
            Error::Initialization(format!("a point wrote {} coordinates", written.len()).into())
        })
    }
}

#[cfg(test)]
mod tests;
