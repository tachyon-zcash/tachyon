//! Typed circuit representations of protocol values.

macro_rules! scalar_gadget {
    ($name:ident, $debug:literal) => {
        #[doc = concat!("Circuit representation of `", stringify!($name), "`.")]
        #[derive(
            ragu_core::gadgets::Gadget,
            ragu_primitives::io::Write,
            derive_more::Debug,
            derive_more::From,
        )]
        #[debug($debug)]
        pub struct $name<'dr, D: ragu_core::drivers::Driver<'dr>> {
            pub(crate) element: ragu_primitives::Element<'dr, D>,
        }
    };
}

pub mod anchor;
pub mod commitment;
pub mod epoch;
pub mod evidence;
pub mod keys;
pub mod note;
pub mod nullifier;
pub mod point;
pub mod profile;
pub mod sets;
pub mod tachygram;
pub mod value;
