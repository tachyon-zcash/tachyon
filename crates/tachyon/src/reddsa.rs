//! RedPallas signature types for Tachyon.
//!
//! Tachyon reuses Orchard's RedPallas basepoints for action and binding
//! signatures. This module re-exports reddsa types under Tachyon-specific
//! names so the rest of the crate avoids direct `reddsa::orchard` imports.

/// RedPallas signature scheme for value-balance binding.
pub(crate) use ::reddsa::orchard::Binding as BindingAuth;
/// RedPallas signature scheme for action authorization.
///
/// Both spend and output actions use the same basepoint.
pub(crate) use ::reddsa::orchard::SpendAuth as ActionAuth;
pub(crate) use ::reddsa::{Error, Signature, SigningKey, VerificationKey, VerificationKeyBytes};
