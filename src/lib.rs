//! Syncloom shared core: protocol types, end-to-end encryption, chunking, merge,
//! name handling, and (with the `client` feature) the HTTP client and sync engine.
pub mod api;
pub mod b64;
pub mod chunking;
pub mod crypto;
pub mod error;
pub mod merge;
pub mod names;
pub mod node;
pub mod vault;

pub use error::{Error, Result};

#[cfg(feature = "grpc")]
pub mod grpc;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "client")]
pub mod state;
#[cfg(feature = "client")]
pub mod sync;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "uniffi")]
pub mod ffi;
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "capi")]
pub mod capi;
