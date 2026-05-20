extern crate alloc;

use alloc::vec::Vec;

use mock_ragu::{Commitment, Multiset, Polynomial};
use pasta_curves::Fp;

use super::{ActionDigest, Tachygram};
use crate::{Action, ActionDigestError};

/// Pedersen commitment to a stamp's tachygram set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TachygramSetCommit(pub Commitment);

/// Pedersen commitment to a stamp's action-digest set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionSetCommit(pub Commitment);

/// Ragu gadget representation of a stamp's tachygram set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TachygramSetGadget(pub Multiset);

/// Ragu gadget representation of a stamp's action-digest set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionSetGadget(pub Multiset);

impl From<&[ActionDigest]> for ActionSetGadget {
    fn from(ads: &[ActionDigest]) -> Self {
        let roots: Vec<Fp> = ads.iter().map(|&ad| Fp::from(ad)).collect();
        let poly = Polynomial::from_roots(&roots);
        Self(Multiset::new(poly))
    }
}

impl From<&[Tachygram]> for TachygramSetGadget {
    fn from(tgs: &[Tachygram]) -> Self {
        let roots: Vec<Fp> = tgs.iter().map(|&tg| Fp::from(tg)).collect();
        let poly = Polynomial::from_roots(&roots);
        Self(Multiset::new(poly))
    }
}

impl From<&[ActionDigest]> for ActionSetCommit {
    fn from(ads: &[ActionDigest]) -> Self {
        let roots: Vec<Fp> = ads.iter().map(|&ad| Fp::from(ad)).collect();
        let poly = Polynomial::from_roots(&roots);
        Self(Multiset::new(poly).commit())
    }
}

impl TryFrom<&[Action]> for ActionSetCommit {
    type Error = ActionDigestError;

    fn try_from(actions: &[Action]) -> Result<Self, Self::Error> {
        let ads: Vec<ActionDigest> = actions
            .iter()
            .map(Action::digest)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()?;
        let roots: Vec<Fp> = ads.into_iter().map(Fp::from).collect();
        let poly = Polynomial::from_roots(&roots);
        Ok(Self(Multiset::new(poly).commit()))
    }
}

impl From<&[Tachygram]> for TachygramSetCommit {
    fn from(tgs: &[Tachygram]) -> Self {
        let roots: Vec<Fp> = tgs.iter().map(|&tg| Fp::from(tg)).collect();
        let poly = Polynomial::from_roots(&roots);
        Self(Multiset::new(poly).commit())
    }
}

impl From<ActionSetGadget> for ActionSetCommit {
    fn from(gadget: ActionSetGadget) -> Self {
        Self(gadget.0.commit())
    }
}

impl From<TachygramSetGadget> for TachygramSetCommit {
    fn from(gadget: TachygramSetGadget) -> Self {
        Self(gadget.0.commit())
    }
}
