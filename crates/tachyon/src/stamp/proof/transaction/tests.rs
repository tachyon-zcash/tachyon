use ragu::{
    circuits::polynomials,
    pasta::Pasta,
    pcd::{bridge_hash, ipa::IpaCycle as _},
    primitives::Simulator,
    udon::curve::Projective as _,
};

use super::*;
use crate::{
    pasta::{self, Fq},
    stamp::proof::new_application,
};

#[test]
fn dehydrate_requires_both_wallet_padding_coordinates() {
    let app = new_application().unwrap();
    let one = app.commit(&[Fp::ONE]).unwrap();
    let (wx, wy) = app.bridge_hash(one).unwrap().coordinates().unwrap();
    // Use the same commitment and shared generator basis, but the rank-15
    // bridge stage's coefficient degrees. No aggregator application is needed.
    let params = pasta::baked();
    let (gx, gy) = bridge_hash::rx::<_, polynomials::AggregatorRank>(one)
        .unwrap()
        .iter_stored_coeffs()
        .filter(|&(_, coefficient)| *coefficient != Fq::ZERO)
        .map(|(index, coefficient)| Pasta::nested_generator(params, index).unwrap() * *coefficient)
        .reduce(|left, right| left + right)
        .unwrap()
        .to_affine()
        .coordinates()
        .unwrap();
    let check = |coords| {
        Simulator::<Fp>::simulate(coords, |dr, xy| {
            let x = Element::alloc(dr, &mut (), xy.as_ref().map(|&(x, _)| x))?;
            let y = Element::alloc(dr, &mut (), xy.map(|(_, y)| y))?;
            TransactionDehydrate::enforce_wallet_padding(dr, &x, &y)
        })
    };
    check((wx, wy)).unwrap();
    for wrong in [(gx, gy), (gx, wy), (wx, gy)] {
        assert!(matches!(check(wrong), Err(ragu::Error::InvalidWitness(_))));
    }
}
