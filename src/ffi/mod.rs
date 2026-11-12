//! The C boundary: the only layer that knows `bindings`. Every export follows
//! the Go handler's three steps: check and convert the caller's input, call
//! the application or a domain service, convert the result back and map
//! errors to `agc_rc` (in `error.rs` only).

// bindgen names C enum constants `agc_<enum>_AGC_<VALUE>`; they appear in patterns.
#![allow(non_upper_case_globals)]

mod context;
mod error;
pub mod exports;
mod guard;
mod last_error;
mod translation;
mod versioned;
