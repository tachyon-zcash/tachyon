//! Action effect markers: [`Spend`] and [`Output`].
//!
//! These zero-sized types parameterize [`Plan`](crate::action::Plan),
//! [`Randomizer`](crate::entropy::Randomizer),
//! [`ActionPrivate`](crate::witness::ActionPrivate), and key types to
//! distinguish spend-side from output-side at compile time.
//!
//! [`Action`](crate::action::Action) is un-parameterized — the effect is
//! erased at authorization time.

mod sealed {
    pub trait Sealed: Send + Sync {}
    impl Sealed for super::Spend {}
    impl Sealed for super::Output {}
}

/// Sealed trait for action effect types.
///
/// Implemented by [`Spend`] and [`Output`].
pub trait Effect: sealed::Sealed {}
impl<T: sealed::Sealed> Effect for T {}

/// Marker type for spend actions.
#[derive(Clone, Copy, Debug)]
pub struct Spend;

/// Marker type for output actions.
#[derive(Clone, Copy, Debug)]
pub struct Output;
