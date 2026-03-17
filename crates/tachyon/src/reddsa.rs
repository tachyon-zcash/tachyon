//! RedPallas type aliases for Tachyon.
//!
//! Tachyon reuses Orchard's RedPallas basepoints for action and binding
//! signatures. This module re-exports reddsa types under Tachyon-specific
//! names so the rest of the crate avoids direct `reddsa::orchard` imports.

use ::reddsa::orchard;
pub(crate) use ::reddsa::{Error, Signature, SigningKey, VerificationKey};

/// RedPallas signature scheme for action authorization.
///
/// Both spend and output actions use the same basepoint.
pub(crate) type ActionAuth = orchard::SpendAuth;

/// RedPallas signature scheme for value-balance binding.
pub(crate) type BindingAuth = orchard::Binding;
