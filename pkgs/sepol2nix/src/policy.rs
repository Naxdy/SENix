//! Shared policy-language syntax: identifier sets, MLS, contexts, extended
//! permissions, constraint/conditional expressions, `m4` and statements.
//!
//! The declarations in here are used by both the type-enforcement (`.te`) and
//! interface (`.if`) grammars, which share the checkpolicy statement language.

pub mod context;
pub mod expr;
pub mod m4;
pub mod mls;
pub mod names;
pub mod statement;
pub mod xperm;
