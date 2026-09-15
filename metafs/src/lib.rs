//! `metafs` — a read-only, xattr-in-memory pass-through FUSE filesystem.
//!
//! See the crate-level documentation of [`fs`] for the design.

pub mod fs;
pub mod xattrs;
