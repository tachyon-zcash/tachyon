//! Semantic gadget records for the application's proof headers.

macro_rules! output_gadget {
    ($name:ident, $debug:literal, { $($field:ident: $kind:ident),* $(,)? }) => {
        #[doc = concat!("The `", stringify!($name), "` header gadget.")]
        #[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug)]
        #[debug($debug)]
        pub struct $name<'dr, D: ragu_core::drivers::Driver<'dr>> {
            $(#[doc = concat!("The `", stringify!($field), "` field.")]
              pub $field: $kind<'dr, D>,)*
        }
    };
}

pub mod delegation;
pub mod evidence;
pub mod output;
pub mod pool;
pub mod qr;
pub mod spend;
pub mod spendable;
pub mod stamp;
pub mod summary;
