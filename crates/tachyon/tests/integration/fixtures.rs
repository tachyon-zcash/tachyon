extern crate alloc;

use alloc::vec::Vec;
use core::ops::Deref;
use std::{sync::Mutex, thread};

use ragu::{
    header::Header,
    step::{Encoded, HeaderInput, Index, Oracles, Step},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    pasta::Pasta,
};
use zcash_tachyon::{
    action,
    bundle::Bundle,
    digest::blake2b,
    fee,
    pasta::Fp,
    stamp::{self, AggregateId, StampState, proof::App},
};

pub mod pool;
pub mod qr;
pub mod wallet;

/// Applications that are not currently leased.
static APPLICATIONS: Mutex<Vec<App<'static>>> = Mutex::new(Vec::new());

/// An application borrowed from the pool until it is dropped.
/// A test that panics mid-proof may leave its application in a state the next
/// test should not inherit.
pub struct ApplicationLease(Option<App<'static>>);

impl Deref for ApplicationLease {
    type Target = App<'static>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl Drop for ApplicationLease {
    fn drop(&mut self) {
        if !thread::panicking() {
            APPLICATIONS.lock().unwrap().push(self.0.take().unwrap());
        }
    }
}

pub fn application() -> ApplicationLease {
    let application = APPLICATIONS.lock().unwrap().pop();
    ApplicationLease(Some(
        application.unwrap_or_else(|| stamp::proof::new_application().unwrap()),
    ))
}

pub(crate) struct WithPolynomials<S>(pub S, pub [Vec<Fp>; 2]);

impl<S: Step<Pasta>> Step<Pasta> for WithPolynomials<S> {
    type Aux<'source> = S::Aux<'source>;
    type Left = S::Left;
    type Output = S::Output;
    type Right = S::Right;
    type Witness<'source> = S::Witness<'source>;

    const INDEX: Index = S::INDEX;
    const NUM_STAGED: usize = S::NUM_STAGED;

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        self.0.staged(witness, left, right)
    }

    fn polynomials(
        &self,
        _: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok(self.1.clone())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        self.0.witness(dr, oracles, witness, left, right)
    }
}

pub fn mock_sighash(bundle_digest: [u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend sighash")
        .to_state()
        .update(&bundle_digest)
        .finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn stamp_coverage(
    descriptors: impl IntoIterator<Item = action::Descriptor>,
    fees: &[fee::Descriptor],
) -> [u8; 32] {
    let mut descriptor_bytes: Vec<[u8; 64]> = descriptors.into_iter().collect();
    descriptor_bytes.sort_unstable();
    let mut fee_bytes: Vec<[u8; 40]> = fees.iter().copied().map(Into::into).collect();
    fee_bytes.sort_unstable();
    blake2b::stamp_coverage_digest(
        &blake2b::action_descriptor_digest(&descriptor_bytes),
        &blake2b::stamp_fees_digest(&fee_bytes),
    )
}

pub fn mock_wtxid<S: StampState + 'static>(bundle: &Bundle<S>) -> AggregateId {
    let txid = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend txid")
        .to_state()
        .update(&bundle.commitment())
        .finalize();
    let auth_digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend auth")
        .to_state()
        .update(&bundle.auth_digest())
        .finalize();
    let mut wtxid = [0u8; 64];
    wtxid[..32].copy_from_slice(txid.as_bytes());
    wtxid[32..].copy_from_slice(auth_digest.as_bytes());
    AggregateId::try_from(wtxid).unwrap()
}
