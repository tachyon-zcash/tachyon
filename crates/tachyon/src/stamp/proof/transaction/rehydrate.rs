//! Confirming a portable wallet bridge against a local aggregator bridge.

#[cfg(test)]
mod tests;

use ragu::{
    Error, Result,
    drivers::{Driver, DriverValue},
    header::Header,
    maybe::Maybe as _,
    pasta::Pasta,
    pcd::profile,
    primitives::Element,
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::curve::Affine as _,
};

use super::{PublicTransaction, Transaction, TransactionOutput};
use crate::{
    ActionSetBridge, ActionSetCommit, ActionSetPoly,
    gadgets::bridge_hash::BridgeConversion,
    pasta::{EqAffine, Fp},
};

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
pub struct TransactionRehydrate(BridgeConversion);

impl TransactionRehydrate {
    /// Constructs the fixed wallet-to-aggregator difference tables.
    ///
    /// # Errors
    /// Propagates Ragu's stage-polynomial and fixed-base setup errors.
    ///
    /// # Panics
    /// If the compiled Ragu stage layout or baked generators no longer match
    /// the pinned coordinate degrees, coverage and mask exclusions.
    pub fn new() -> Result<Self> {
        BridgeConversion::new().map(Self)
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
        let local = self.0.enforce_same_coordinates(
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
