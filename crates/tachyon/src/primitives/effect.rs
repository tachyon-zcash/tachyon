//! Compile-time effect markers for spend vs output actions.
//!
//! [`Spend`] and [`Output`] are zero-sized marker types that parameterize
//! [`Plan`](crate::action::Plan),
//! [`ActionRandomizer`](crate::entropy::ActionRandomizer),
//! [`ActionSigningKey`](crate::keys::planner::ActionSigningKey), and key types
//! to enforce the spend/output distinction at compile time.

mod sealed {
    pub trait Sealed: Send + Sync {}
    impl Sealed for super::Spend {}
    impl Sealed for super::Output {}
}

/// Sealed trait marking an action effect (spend or output).
pub trait Effect: Copy + sealed::Sealed {}
impl<T: Copy + sealed::Sealed> Effect for T {}

/// Spend effect marker.
#[derive(Clone, Copy, Debug)]
pub struct Spend;

/// Output effect marker.
#[derive(Clone, Copy, Debug)]
pub struct Output;
