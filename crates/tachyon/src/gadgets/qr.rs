//! QR profiles inside a circuit.

use ragu::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe as _,
    primitives::{Boolean, Element, GadgetExt as _, allocator::Allocator, io::Write},
    udon::field::Field as _,
};

use crate::{
    collections::qr::QUADRATIC_NON_RESIDUE,
    pasta::Fp,
    primitives::{self, QrClass, QrClassRoot},
};

/// An in-circuit [`QrProfile`](primitives::QrProfile) holding the number of
/// sides taken and those sides as bits.
///
/// Allocation adds no constraint, so the two wires form a
/// [path](primitives::QrProfile#injectivity) only where a step proves it.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "a gadget holds driver wires, like the header gadgets it sits in"
)]
pub struct QrProfile<'dr, D: Driver<'dr>> {
    pub depth: Element<'dr, D>,
    pub bits: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr, F = Fp>> QrProfile<'dr, D> {
    /// Allocates a header's profile as two unconstrained wires.
    pub(crate) fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        profile: DriverValue<D, primitives::QrProfile>,
    ) -> Result<Self> {
        Ok(Self {
            depth: Element::alloc(
                dr,
                allocator,
                profile
                    .as_ref()
                    .map(|value| Fp::from(u64::from(value.depth))),
            )?,
            bits: Element::alloc(
                dr,
                allocator,
                profile.map(|value| Fp::from(u64::from(value.bits))),
            )?,
        })
    }

    /// The depth-zero profile, as constants.
    pub(crate) fn root(dr: &mut D) -> Self {
        Self {
            depth: Element::constant(dr, Fp::from(u64::from(primitives::QrProfile::ROOT.depth))),
            bits: Element::constant(dr, Fp::from(u64::from(primitives::QrProfile::ROOT.bits))),
        }
    }

    /// The child profile on side `bit`.
    ///
    /// # Soundness
    ///
    /// The range check bounds the parent's `depth` to an integer $j$ below
    /// `MAX_DEPTH`, giving the child depth $j+1$. When the parent is a path,
    /// its `bits` lie below $2^j$, so $2 \cdot \mathsf{bits} + b < 2^{j+1}$
    /// appends $b$ without wrapping.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn descend(&self, dr: &mut D, bit: &Boolean<'dr, D>) -> Result<Self> {
        self.depth
            .enforce_lt::<{ primitives::QrProfile::MAX_DEPTH.ilog2() as usize }>(
                dr,
                &mut (),
                Fp::from(primitives::QrProfile::MAX_DEPTH as u64),
            )?;
        let one = Element::constant(dr, Fp::ONE);
        Ok(Self {
            depth: self.depth.add(dr, &one),
            bits: self.bits.double(dr).add(dr, &bit.element()),
        })
    }

    /// Proves that `value`'s first `depth` QR sides are this profile's bits.
    ///
    /// At each of 32 positions, `path` gives class bit $b_j$ and `roots` gives
    /// $r_j$ satisfying $r_j^2=m_j(x+R_j)$ for $R_j=R_0+j$ from `discriminant`.
    /// Unlike descent, $m_j=c-(c-1)b_j$ uses the queried class, not its
    /// sibling, with fixed non-residue $c$. The mask $e_j$ selects the
    /// profile bits under
    ///
    /// $$
    ///   \sum_j e_j = \mathsf{depth},
    ///   \qquad
    ///   2 \sum_j j \cdot e_j = \mathsf{depth} \cdot (\mathsf{depth} - 1),
    ///   \qquad
    ///   a_{j+1} = a_j + e_j \cdot (a_j + b_j),
    /// $$
    ///
    /// with $a_0 = 0$ and the last $a$ equal to `bits`.
    ///
    /// # Soundness
    ///
    /// For $b_j=1$ the root [shows](crate::collections::qr#sides) a square or
    /// zero; for $b_j=0$ the root and the nonzero check on $x+R_j$ show a
    /// non-residue. Boolean mask bits give integer depth $d$ in
    /// `0..=MAX_DEPTH`, so the index-sum equation holds over the integers.
    /// Only the first $d$ positions attain the minimum sum $d(d-1)/2$. The
    /// fold doubles $a$ and adds $b_j$ on this prefix, then leaves it
    /// unchanged: `bits` is $\sum_{j<d} b_j 2^{d-1-j}<2^{32}$
    /// without wrapping. Thus the profile is $x$'s depth-$d$
    /// [path](primitives::QrProfile#injectivity) at $R_0$ for any
    /// satisfying input wires, with no challenge.
    #[expect(clippy::indexing_slicing, reason = "fixed 32-position profile arrays")]
    pub(crate) fn enforce_sides_of(
        &self,
        dr: &mut D,
        value: &Element<'dr, D>,
        discriminant: &Element<'dr, D>,
        path: DriverValue<D, [QrClass; primitives::QrProfile::MAX_DEPTH]>,
        roots: DriverValue<D, [QrClassRoot; primitives::QrProfile::MAX_DEPTH]>,
        mask: DriverValue<D, [bool; primitives::QrProfile::MAX_DEPTH]>,
    ) -> Result<()> {
        let mut shifted = value.add(dr, discriminant);
        let mut depth_acc = Element::constant(dr, Fp::ZERO);
        let mut index_acc = Element::constant(dr, Fp::ZERO);
        let mut bits_acc = Element::constant(dr, Fp::ZERO);
        let one = Element::constant(dr, Fp::ONE);
        let non_residue = Element::constant(dr, QUADRATIC_NON_RESIDUE);
        let mut position_element = Element::constant(dr, Fp::ZERO);
        for position in 0..primitives::QrProfile::MAX_DEPTH {
            let side = Boolean::alloc(
                dr,
                &mut (),
                path.as_ref().map(|classes| classes[position].bit()),
            )?;
            let root = Element::alloc(
                dr,
                &mut (),
                roots.as_ref().map(|values| Fp::from(values[position])),
            )?;
            let selected =
                Boolean::alloc(dr, &mut (), mask.as_ref().map(|values| values[position]))?;
            let multiplier = side.conditional_select(dr, &non_residue, &one)?;
            let expected_square = multiplier.mul(dr, &shifted)?;
            root.square(dr)?.enforce_equal(dr, &expected_square)?;
            side.conditional_select(dr, &shifted, &one)?
                .enforce_nonzero(dr)?;
            depth_acc = depth_acc.add(dr, &selected.element());
            let index_term = selected.element().mul(dr, &position_element)?;
            index_acc = index_acc.add(dr, &index_term);
            let extended_bits = bits_acc.add(dr, &side.element());
            let bits_term = selected.element().mul(dr, &extended_bits)?;
            bits_acc = bits_acc.add(dr, &bits_term);
            shifted = shifted.add(dr, &one);
            position_element = position_element.add(dr, &one);
        }
        depth_acc.enforce_equal(dr, &self.depth)?;
        let depth_minus_one = depth_acc.sub(dr, &one);
        let expected_index_sum = depth_acc.mul(dr, &depth_minus_one)?;
        index_acc
            .double(dr)
            .enforce_equal(dr, &expected_index_sum)?;
        bits_acc.enforce_equal(dr, &self.bits)?;
        Ok(())
    }
}
