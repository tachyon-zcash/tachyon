//! Transport of an authenticated span through a padding-only wallet statement.

use alloc::vec::Vec;
use core::iter;

use ragu::{Rank as _, WalletRank, pasta::Pasta, pcd::profile, udon::curve::Affine as _};

use super::*;
use crate::{
    AnchorSetCommit, gadgets::bridge_hash::BridgeConversion, pasta::EqAffine,
    primitives::coefficients, stamp::proof::transaction::TransactionDehydrate,
};

/// A wallet-issued span's endpoints and prefix binding. Both online slots are
/// padding.
#[derive(Debug)]
pub struct PublicAnchorSpan;

impl Header<Fp> for PublicAnchorSpan {
    type Data = <AnchorSpan as Header<Fp>>::Data;
    type OnlinePolyCommit = (Padding, Padding);
    type Output = <AnchorSpan as Header<Fp>>::Output;

    const SUFFIX: Suffix = Suffix::new(18);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        AnchorSpan::encode(dr, allocator, witness)
    }
}

/// Copy the authenticated span fields. The own output's padding bridge pins
/// ordinary issuance to the wallet basis, independently of the prefix binding.
#[derive(Debug)]
pub struct AnchorSpanDehydrate;

impl<C: Cycle<CircuitField = Fp>> Step<C> for AnchorSpanDehydrate {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = PublicAnchorSpan;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(41);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <AnchorSpan as Header<Fp>>::Data>,
        right: DriverValue<D, ()>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, AnchorSpan, N>,
            Encoded<'dr, D, (), N>,
            Encoded<'dr, D, PublicAnchorSpan, N>,
        ),
        DriverValue<D, <PublicAnchorSpan as Header<Fp>>::Data>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let oracle = oracles.bridge_hash();
        TransactionDehydrate::enforce_wallet_padding(dr, oracle.x(), oracle.y())?;
        let span = Encoded::<D, AnchorSpan, N>::new(dr, &mut (), left.clone())?;
        let unit = Encoded::new(dr, &mut (), right)?;
        let output = Encoded::from_gadget(span.as_gadget().clone());
        Ok(((span, unit, output), left, D::unit()))
    }
}

/// Restore a full span from its wallet statement and candidate prefix.
///
/// Both output polynomials are committed before the challenge. The bridge
/// conversion binds Q; the authenticated end and the product check bind M.
#[derive(Clone, Debug)]
pub struct AnchorSpanRehydrate(BridgeConversion);

impl AnchorSpanRehydrate {
    /// Configure the fixed wallet-to-aggregator difference tables.
    ///
    /// # Errors
    /// Propagates Ragu's stage and fixed-base setup errors.
    ///
    /// # Panics
    /// If the compiled stage layout or generators violate the pinned layout.
    pub fn new() -> ragu::Result<Self> {
        BridgeConversion::new().map(Self)
    }
}

impl<C: profile::ProfiledCycle<Base = Pasta, CircuitField = Fp>> Step<C> for AnchorSpanRehydrate {
    type Aux<'source> = ();
    type Left = PublicAnchorSpan;
    type Output = AnchorSpan;
    type Right = ();
    type Witness<'source> = (AnchorSetPoly, AnchorSetCommit);

    const INDEX: Index = Index::new(42);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, PublicAnchorSpan>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> ragu::Result<Prepared<Fp, AnchorSpan>> {
        let prefix = coefficients(witness.0.as_ref());
        if prefix.len() >= WalletRank::num_coeffs() {
            return Err(ragu::Error::InvalidWitness(
                "span members exceed the wallet degree bound".into(),
            ));
        }
        let end = Fp::from(left.data.1);
        let members = iter::once(Fp::ZERO)
            .chain(prefix.iter().copied())
            .zip(prefix.iter().copied().chain([Fp::ZERO]))
            .map(|(previous, current)| previous - end * current)
            .collect::<Vec<_>>();
        Ok(Prepared::new()
            .poly(AnchorSetPoly::SLOT, members)
            .poly(AnchorSpanBridgeSlot, prefix))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <PublicAnchorSpan as Header<Fp>>::Data>,
        right: DriverValue<D, ()>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, PublicAnchorSpan, N>,
            Encoded<'dr, D, (), N>,
            Encoded<'dr, D, AnchorSpan, N>,
        ),
        DriverValue<D, <AnchorSpan as Header<Fp>>::Data>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let span = Encoded::<D, PublicAnchorSpan, N>::new(dr, &mut (), left.clone())?;
        let unit = Encoded::new(dr, &mut (), right)?;
        let (endpoints, (wallet_x, wallet_y)) = span.as_gadget().clone();
        let z = oracles.zeta().clone();
        let members = oracles.output(AnchorSetPoly::SLOT).open(dr, &z)?;
        let prefix = oracles.output(AnchorSpanBridgeSlot).open(dr, &z)?;
        span::enforce_end_factor(dr, &z, &endpoints.anchor_end, &prefix, &members)?;
        let oracle = oracles.bridge_hash();
        let coords = D::try_just(|| {
            EqAffine::from(witness.take().1)
                .coordinates()
                .map(Into::into)
                .ok_or_else(|| ragu::Error::InvalidWitness("identity prefix commitment".into()))
        })?;
        let local = self.0.enforce_same_coordinates(
            dr,
            [&wallet_x, &wallet_y],
            [oracle.x(), oracle.y()],
            coords,
        )?;
        let data = D::just(|| {
            let (start, end, _) = left.take();
            (start, end, local.value().take().into())
        });
        let out = Encoded::from_gadget((endpoints, (oracle.x().clone(), oracle.y().clone())));
        Ok(((span, unit, out), data, D::unit()))
    }
}
