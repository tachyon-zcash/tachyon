use crate::primitives::Fp;
use ragu_arithmetic::CurveAffine;
use ragu_core::Result;
use ragu_core::drivers::{Driver, DriverValue};
use ragu_core::gadgets::{GadgetKind, Kind};
use ragu_core::maybe::Maybe;
use ragu_pasta::EpAffine;
use ragu_pcd::header::{Header, Suffix};
use ragu_primitives::{Element, Point};

/// Succinct stamp state carried through the PCD tree.
///
/// Two Pedersen multiset hash accumulators (curve points on Pallas) and an
/// accumulator state anchor.  The proof privately binds $\hat{d}$ to
/// $\widehat{Tg}$ and provides the only verifiable link between an action
/// and its tachygram.
///
/// The anchor doubles as the nullifier flavor: the circuit uses it for
/// accumulator membership ($cmx \in \text{acc}(\text{anchor})$) and as
/// the flavor input to nullifier derivation ($nf = F_{mk}(\text{anchor})$).
pub(super) struct StampDigest;

/// Raw data for the [`StampDigest`] header.
#[derive(Clone, Debug)]
pub struct StampDigestData {
    /// Action digest accumulator $\hat{d}$.
    pub actions_acc: EpAffine,
    /// Tachygram accumulator $\widehat{Tg}$.
    pub tachygram_acc: EpAffine,
    /// Accumulator state anchor / nullifier flavor.
    pub anchor: Fp,
}

/// Gadget representation of [`StampDigestData`].
///
/// Constrains `D::F = Fp` so that `Point<'dr, D, EpAffine>` is well-formed
/// (Pallas base field = Fp).  The [`Write`](ragu_primitives::io::Write) derive
/// serialises `(actions_acc.x, actions_acc.y, tachygram_acc.x,
/// tachygram_acc.y, anchor)` — five field elements.
#[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write)]
pub(super) struct StampDigestGadget<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// $\hat{d}$ accumulator point.
    #[ragu(gadget)]
    pub actions_acc: Point<'dr, D, C>,
    /// $\widehat{Tg}$ accumulator point.
    #[ragu(gadget)]
    pub tachygram_acc: Point<'dr, D, C>,
    /// Accumulator state anchor / nullifier flavor.
    #[ragu(gadget)]
    pub anchor: Element<'dr, D>,
}

impl Header<Fp> for StampDigest {
    const SUFFIX: Suffix = Suffix::new(0);
    /// `(actions_acc, tachygram_acc, anchor)`
    type Data<'source> = (EpAffine, EpAffine, Fp);

    /// Five field elements via [`StampDigestGadget`].
    type Output = Kind![Fp; StampDigestGadget<'_, _, EpAffine>];

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
        let (actions_acc, tachygram_acc, anchor) = witness.cast();
        Ok(StampDigestGadget {
            actions_acc: Point::alloc(dr, actions_acc)?,
            tachygram_acc: Point::alloc(dr, tachygram_acc)?,
            anchor: Element::alloc(dr, anchor)?,
        })
    }
}
