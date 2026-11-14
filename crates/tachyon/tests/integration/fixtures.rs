extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::ops::Deref;
use std::{sync::Mutex, thread};

use ragu_core::{
    drivers::{Driver, DriverValue},
    pasta::Pasta,
};
use ragu_pcd::{
    header::Header,
    step::{Encoded, HeaderInput, Index, Oracles, Step},
};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    bundle::Bundle,
    pasta::Fp,
    stamp::{self, StampState, proof::App},
};

pub mod pool;
pub mod qr;
pub mod wallet;

/// Applications that are not currently leased.
static APPLICATIONS: Mutex<Vec<Box<App<'static>>>> = Mutex::new(Vec::new());

/// An application borrowed from the pool until it is dropped.
/// A test that panics mid-proof may leave its application in a state the next
/// test should not inherit.
pub struct ApplicationLease(Option<Box<App<'static>>>);

impl Deref for ApplicationLease {
    type Target = App<'static>;

    fn deref(&self) -> &Self::Target {
        self.0.as_deref().unwrap()
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

pub(crate) fn keyed_rng(name: &str, key: &[u8]) -> StdRng {
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"Tachyon-FixtRng")
        .to_state()
        .update(name.as_bytes())
        .update(&[0])
        .update(key)
        .finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(digest.as_bytes());
    StdRng::from_seed(seed)
}

/// Values that their key determines, each proved once for the process.
pub(crate) struct Proved<V> {
    name: &'static str,
    slots: Mutex<BTreeMap<Vec<u8>, Arc<Mutex<Option<V>>>>>,
}

impl<V: Clone> Proved<V> {
    pub(crate) const fn new(name: &'static str) -> Self {
        Self {
            name,
            slots: Mutex::new(BTreeMap::new()),
        }
    }

    /// The value under `key`. The first caller proves it, with an rng seeded
    /// from this fixture's name and the key. A caller that asks while it is
    /// being proved waits. If proving panicked, every later caller panics too.
    pub(crate) fn get(&self, key: &[u8], prove: impl FnOnce(&mut StdRng) -> V) -> V {
        let slot = {
            let mut slots = self.slots.lock().unwrap();
            Arc::clone(slots.entry(key.to_vec()).or_default())
        };
        let name = self.name;
        let mut stored = slot
            .lock()
            .unwrap_or_else(|_| panic!("{name} failed to prove"));
        if stored.is_none() {
            *stored = Some(prove(&mut keyed_rng(name, key)));
        }
        stored.as_ref().unwrap().clone()
    }
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

pub fn mock_txid<S: StampState + 'static>(bundle: &Bundle<S>) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"pretend txid")
        .to_state()
        .update(&bundle.commitment())
        .finalize();
    let mut txid = [0u8; 32];
    txid.copy_from_slice(hash.as_bytes());
    txid
}
