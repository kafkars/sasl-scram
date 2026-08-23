//! Consuming client states for complete enabled SCRAM algorithm profiles.

mod begin;
mod config;
mod derivation;
mod server_final;
mod server_first;

const CLIENT_NONCE_ENTROPY_BYTES: usize = 15;
const CLIENT_NONCE_BYTES: usize = 20;

pub use begin::{AwaitingServerFirst, Client};
pub use config::{ClientConfig, ClientConfigBuilder};
pub use derivation::PendingDerivation;
pub use server_final::{AwaitingServerFinal, ClientAuthenticated};
