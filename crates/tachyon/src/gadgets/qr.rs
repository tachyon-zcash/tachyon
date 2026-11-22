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
    primitives::{self, QrClassRoot},
};

/// A [`QrProfile`](primitives::QrProfile) inside a circuit: the number of
/// sides taken and those sides as bits.
///
/// Allocation places no constraint, so the two wires are a
/// [path](primitives::QrProfile#injectivity) only where a step shows it.
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
    /// Allocates a header's profile as two wires, without a constraint.
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
    /// The range check holds the parent's `depth` to an integer $d$ below
    /// `MAX_DEPTH`. The child has `depth` $d + 1$ and `bits` $2 \cdot
    /// \mathsf{bits} + b$. When the parent is a path, the child is that path
    /// followed by $b$, and its `bits` stay below $2^{d+1}$.
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
    /// Each of the `MAX_DEPTH` positions $j$ allocates a side $b_j$, a root
    /// $r_j$ and a mask bit $m_j$. With $x$ the value, $R_0$ the discriminant,
    /// $s_j = x + R_0 + j$ and $n$ the fixed non-residue, the constraints are
    ///
    /// $$
    ///   r_j^2 = \bigl(n - (n - 1) \cdot b_j\bigr) \cdot s_j,
    ///   \qquad
    ///   b_j = 0 \implies s_j \neq 0,
    /// $$
    ///
    /// $$
    ///   \sum_j m_j = \mathsf{depth},
    ///   \qquad
    ///   2 \sum_j j \cdot m_j = \mathsf{depth} \cdot (\mathsf{depth} - 1),
    ///   \qquad
    ///   a_{j+1} = a_j + m_j \cdot (a_j + b_j),
    /// $$
    ///
    /// with $a_0 = 0$ and the last $a$ equal to `bits`.
    ///
    /// # Soundness
    ///
    /// With $b_j = 1$ the root [shows](crate::collections::qr#sides) that
    /// $s_j$ is a square or zero, and with $b_j = 0$ the root and $s_j \neq 0$
    /// show a non-residue, so $b_j$ is the side of $x$ at $R_0 + j$. The mask
    /// bits are boolean, so `depth` is an integer $d$ from $0$ to `MAX_DEPTH`
    /// and the second equation holds over the integers. Among $d$ distinct
    /// positions the sum is at least $d \cdot (d - 1)/2$, and only the first
    /// $d$ reach it, so the mask is $d$ ones followed by zeros. The fold then
    /// doubles $a$ and adds $b_j$ at each of the first $d$ positions and
    /// leaves it unchanged after. The profile is thus the
    /// [path](primitives::QrProfile#injectivity) of the first $d$ sides of
    /// $x$, and $x$ is in its class at $R_0$. The gadget reads no challenge
    /// and holds for whatever wires it is given.
    #[expect(clippy::indexing_slicing, reason = "fixed 32-position profile arrays")]
    pub(crate) fn enforce_sides_of(
        &self,
        dr: &mut D,
        value: &Element<'dr, D>,
        discriminant: &Element<'dr, D>,
        classes: DriverValue<D, [QrClassRoot; primitives::QrProfile::MAX_DEPTH]>,
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
                classes.as_ref().map(|values| values[position].0),
            )?;
            let root = Element::alloc(
                dr,
                &mut (),
                classes.as_ref().map(|values| values[position].1),
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
