//! The C boundary: the only layer that knows `bindings`. Every export follows
//! the Go handler's three steps: check and convert the caller's input, call
//! the application or a domain service, convert the result back and map
//! errors to `agc_rc` (in `error.rs` only).

mod context;
mod error;
pub mod exports;
mod guard;
mod last_error;
mod secure_memory;
mod translation;
mod versioned;
