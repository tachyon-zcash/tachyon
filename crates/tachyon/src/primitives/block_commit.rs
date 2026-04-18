use pasta_curves::Fp;

/// Per-block tachygram set commitment.
///
/// Each block commits to its tachygram set. SpendableInit verifies
/// inclusion against this commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockCommit(Fp);

impl From<BlockCommit> for Fp {
    fn from(bc: BlockCommit) -> Self {
        bc.0
    }
}

impl From<Fp> for BlockCommit {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}
