use pasta_curves::Fp;

/// A tachygram is a field element ($\mathbb{F}_p$) representing either a
/// note commitment or a nullifier in the Tachyon polynomial accumulator.
///
/// The accumulator does not distinguish between commitments and nullifiers.
/// This unified approach simplifies the proof system and enables efficient
/// batch operations.
///
/// The number of tachygrams in a stamp need not equal the number of
/// actions. The invariant is consistency between the listed tachygrams
/// and the proof's `tachygram_acc`, not a fixed ratio to actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tachygram(Fp);

impl From<Fp> for Tachygram {
    fn from(f: Fp) -> Self {
        Self(f)
    }
}

impl From<Tachygram> for Fp {
    fn from(tg: Tachygram) -> Self {
        tg.0
    }
}

/// A tachyon epoch — a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Used as **flavor** in nullifier derivation:
/// $mk = \text{KDF}(\psi, nk)$, then $nf = F_{mk}(\text{flavor})$.
/// Different epochs produce different nullifiers for the same note,
/// enabling range-restricted delegation via the GGM tree PRF.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, PartialEq, Eq)]
pub struct Epoch(Fp);

impl From<Fp> for Epoch {
    fn from(f: Fp) -> Self {
        Self(f)
    }
}

impl From<Epoch> for Fp {
    fn from(e: Epoch) -> Self {
        e.0
    }
}

/// A reference to a specific tachyon accumulator state.
///
/// The tachyon accumulator is append-only: the state at epoch N is a
/// subset of the state at epoch M for M > N. This means membership
/// proofs valid at an earlier state remain valid at all later states.
///
/// When stamps are merged during aggregation, the later anchor
/// subsumes the earlier — "analogous to the max of all aggregated
/// anchors" (the most recent state covers everything the earlier
/// states covered).
///
/// Range validation (checking that the anchor falls within the valid
/// epoch window for the landing block) is performed by the consensus
/// layer outside the circuit.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, PartialEq, Eq)]
pub struct Anchor(pub Fp);

impl From<Fp> for Anchor {
    fn from(f: Fp) -> Self {
        Self(f)
    }
}

impl From<Anchor> for Fp {
    fn from(a: Anchor) -> Self {
        a.0
    }
}
