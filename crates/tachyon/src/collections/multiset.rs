extern crate alloc;

use alloc::vec::Vec;

use ragu::{Polynomial, ProductionRank};

use crate::{arithmetic, pasta::Fp};

/// Encode the provided members as roots.
pub(crate) fn encode(members: impl IntoIterator<Item = Fp>) -> Polynomial<Fp, ProductionRank> {
    let roots: Vec<Fp> = members.into_iter().collect();
    Polynomial::from_coeffs(arithmetic::poly_with_roots(&roots))
}
