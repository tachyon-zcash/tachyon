//! Ragu's field aliases and baked parameters under one namespace.
//!
//! `ragu_core` and `ragu_pcd` each have a `pasta` module, and a file that
//! needs both can import only one of them under that name.

pub(crate) use ragu_core::pasta::{Fp, Fq};
pub(crate) use ragu_pcd::pasta::baked;
