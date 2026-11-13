//! Protocol-wide constants.

pub(crate) mod orchard {
    //! Orchard-derived generators shared by native code and circuit gadgets.

    use group::GroupEncoding as _;
    use lazy_static::lazy_static;
    use pasta_curves::{arithmetic::CurveExt as _, pallas::Point};
    use udon::curve::Affine as _;

    use crate::pasta::{Ep, EpAffine};

    /// Orchard's value-commitment domain (§5.4.8.3).
    const VALUE_COMMITMENT_DOMAIN: &str = "z.cash:Orchard-cv";

    /// Orchard's spend-authorization domain, also used for Tachyon actions.
    const ACTION_AUTH_DOMAIN: &str = "z.cash:Orchard";

    lazy_static! {
        /// Generator $\mathcal{V}$ for value commitments.
        pub(crate) static ref VALUE_COMMIT_V: Ep = {
            #[expect(clippy::expect_used, reason = "the fixed generator has a canonical encoding")]
            EpAffine::from_bytes(Point::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"v").to_bytes())
                .expect("valid Orchard generator")
                .to_projective()
        };

        /// Generator $\mathcal{R}$ for value commitments and binding signatures.
        pub(crate) static ref VALUE_COMMIT_R: Ep = {
            #[expect(clippy::expect_used, reason = "the fixed generator has a canonical encoding")]
            EpAffine::from_bytes(Point::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"r").to_bytes())
                .expect("valid Orchard generator")
                .to_projective()
        };

        /// Orchard RedPallas action-authorizing generator.
        pub(crate) static ref ACTION_AUTH_GENERATOR: Ep = {
            #[expect(clippy::expect_used, reason = "the fixed generator has a canonical encoding")]
            EpAffine::from_bytes(Point::hash_to_curve(ACTION_AUTH_DOMAIN)(b"G").to_bytes())
                .expect("valid Orchard generator")
                .to_projective()
        };
    }
}

/// Maximum representable value in zatoshis (§5.3 of the protocol spec).
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;

/// Maximum block height (the protocol spec uses u32).
pub const BLOCK_MAX: u32 = u32::MAX;

/// Number of blocks per epoch. Must be a power of two (block-height
/// arithmetic derives its shift and mask from this value).
pub const EPOCH_SIZE: u32 = if cfg!(feature = "test-epoch-size") {
    64
} else {
    4096
};

/// Maximum epoch index: every block height maps to an epoch.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "the trailing epoch is partial; flooring is the intended index"
)]
pub const EPOCH_MAX: u32 = BLOCK_MAX / EPOCH_SIZE;

/// Children of one node of the evidence tree.
pub const EVIDENCE_TREE_ARITY: usize = 4;
