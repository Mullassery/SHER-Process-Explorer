//! Hand-rolled `/proc` parsers, one module per data domain. Every function
//! here takes a `root: &Path` (the caller passes `/proc` in production,
//! a fixture directory in tests) so none of this needs real Linux or root
//! privileges to unit-test.

pub mod cgroup;
pub mod common;
pub mod files;
pub mod io;
pub mod memory;
pub mod namespace;
pub mod net;
pub mod process;
pub mod security;
pub mod threads;
