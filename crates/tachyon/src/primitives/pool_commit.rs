use pasta_curves::Fp;

/// Cumulative epoch tachygram commitment.
///
/// Serves as the non-membership root for OSS proofs and as the anchor
/// commitment for consensus verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolCommit(Fp);

impl From<PoolCommit> for Fp {
    fn from(pc: PoolCommit) -> Self {
        pc.0
    }
}

impl From<Fp> for PoolCommit {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}
