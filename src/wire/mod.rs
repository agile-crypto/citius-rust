//! The byte formats the C API publishes (DDD's published language): what
//! callers store and exchange, so no domain owns them. Like the generated
//! `proto` types, these are shared by the application layer, the adapters
//! and `ffi`; a domain never encodes or decodes (tests/architecture.rs).

pub mod metadata;
