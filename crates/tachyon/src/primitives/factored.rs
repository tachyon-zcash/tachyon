use pasta_curves::{Eq, Fp};

/// A polynomial carried as the multiset of its irreducible factors instead of
/// as a coefficient vector.
///
/// The encodings behind these witnesses factor uniquely -- a
/// [set](super::TachygramSetPoly) into the linear terms of its members, a
/// [sequence](super::NfSeqPoly) into one irreducible cubic per indexed member
/// -- so the factor multiset *is* the polynomial. Every operation the proof
/// system asks of one is then multiset bookkeeping: a product adds
/// multiplicities, a quotient subtracts them, and an evaluation streams over
/// the factors. Coefficients are realized only to compute
/// [`commitment`](Self::commitment), lazily, and memoized from there.
///
/// The operators are the everyday spelling: `*=` and `*` multiply factors in,
/// `/=` and `/` divide them out.
pub trait FactoredPoly {
    /// Deterministic (untrapdoored) commitment to the encoded polynomial,
    /// memoized until the factors change.
    ///
    /// # Panics
    ///
    /// If realizing the coefficients exceeds the polynomial coefficient cap.
    fn commitment(&self) -> Eq;

    /// The encoded polynomial's value at `x`, streamed over the factors
    /// without realizing coefficients.
    fn eval(&self, x: Fp) -> Fp;

    /// Multiply in every factor of `other`, adding multiplicities. Spelled
    /// `*=`.
    fn add_factors(&mut self, other: &Self);

    /// Divide out every factor of `other`, subtracting multiplicities.
    /// Spelled `/=`.
    ///
    /// This is multiset difference: a factor `other` holds more often than
    /// `self` does comes out only as often as `self` has it, and `other`
    /// divides `self` exactly when no such factor exists. Dividing by a
    /// non-divisor therefore leaves something that is not a quotient, and
    /// the divisibility relations reject that witness rather than take it
    /// for one.
    fn rm_factors(&mut self, other: &Self);
}

/// Implements [`FactoredPoly`] and its operators for a newtype over a factor
/// multiset (any collection offering `commit`, `eval`, `add_factors` and
/// `rm_factors`).
///
/// The operators delegate: `*=` to [`FactoredPoly::add_factors`] and `/=` to
/// [`FactoredPoly::rm_factors`], with `*` and `/` cloning the left operand.
/// They cannot be blanket-implemented over the trait -- `core::ops` is
/// foreign and a bare type parameter is not a local type -- so each wrapper
/// takes them through here.
///
/// The invoking module must have [`FactoredPoly`], [`struct@Eq`], [`Fp`] and
/// the four `core::ops` traits in scope.
macro_rules! impl_factored_poly {
    ($poly:ty) => {
        impl FactoredPoly for $poly {
            fn commitment(&self) -> Eq {
                self.0.commit()
            }

            fn eval(&self, x: Fp) -> Fp {
                self.0.eval(x)
            }

            fn add_factors(&mut self, other: &Self) {
                self.0.add_factors(&other.0);
            }

            fn rm_factors(&mut self, other: &Self) {
                self.0.rm_factors(&other.0);
            }
        }

        impl MulAssign<&Self> for $poly {
            fn mul_assign(&mut self, rhs: &Self) {
                self.add_factors(rhs);
            }
        }

        impl DivAssign<&Self> for $poly {
            fn div_assign(&mut self, rhs: &Self) {
                self.rm_factors(rhs);
            }
        }

        impl Mul<&$poly> for &$poly {
            type Output = $poly;

            fn mul(self, rhs: &$poly) -> $poly {
                let mut product = self.clone();
                product *= rhs;
                product
            }
        }

        impl Div<&$poly> for &$poly {
            type Output = $poly;

            fn div(self, rhs: &$poly) -> $poly {
                let mut quotient = self.clone();
                quotient /= rhs;
                quotient
            }
        }
    };
}

pub(crate) use impl_factored_poly;
