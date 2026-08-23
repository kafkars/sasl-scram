//! Strict, sans-I/O SCRAM protocol engine.
//!
//! This scaffold provides bounded transcript-preserving message parsers,
//! canonical encoders, exact transcript assembly, explicit credential,
//! channel-binding, policy, and secret types, and consuming SCRAM-SHA-256 client
//! and server roles, including SHA-256-PLUS. The opt-in `sha512` feature adds
//! the widely deployed, unregistered SHA-512 extension profile. Both profiles
//! retain explicit derivation and application continuations.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod algorithm;
mod attribute_name;
mod authentication;
mod channel_binding;
#[cfg(any(feature = "sha256", feature = "sha512"))]
mod client;
mod credentials;
#[cfg(any(feature = "sha256", feature = "sha512"))]
mod crypto;
mod error;
mod identity;
mod limits;
mod nonce;
mod outbound;
mod policy;
mod policy_error;
mod preparation;
mod salt;
#[cfg(feature = "saslprep")]
mod saslprep;
mod secret;
#[cfg(any(feature = "sha256", feature = "sha512"))]
mod server;

pub mod message;

pub use algorithm::Algorithm;
pub use attribute_name::AttributeName;
pub use authentication::{AuthenticationProperties, ChannelBindingOutcome};
pub use channel_binding::{
    ChannelBinding, ChannelBindingData, ChannelBindingMode, ChannelBindingName,
};
#[cfg(any(feature = "sha256", feature = "sha512"))]
pub use client::{
    AwaitingServerFinal, AwaitingServerFirst, Client, ClientAuthenticated, ClientConfig,
    ClientConfigBuilder, PendingDerivation,
};
pub use credentials::{PreparedCredentials, PreparedPassword};
pub use error::{
    AuthenticationError, CryptoError, Error, PeerError, PreparationError, ProtocolError, StateError,
};
pub use identity::{
    PreparedAuthenticationIdentity, PreparedAuthorizationIdentity, ReceivedAuthenticationIdentity,
    ReceivedAuthorizationIdentity,
};
pub use limits::{IterationCount, IterationPolicy, ResourceLimits, ResourceLimitsBuilder};
pub use nonce::{NonceError, NonceSource};
pub use outbound::OutboundMessage;
pub use policy::{ClientPolicy, ServerPolicy};
pub use policy_error::PolicyError;
pub use preparation::AsciiProfile;
#[cfg(feature = "saslprep")]
pub use preparation::Rfc5802Profile;
pub use salt::{Salt, SaltPolicy};
pub use secret::{SecretBytes, SecretString};
#[cfg(any(feature = "sha256", feature = "sha512"))]
pub use server::{
    AuthorizationOutcome, AuthorizationRequest, AwaitingClientFinal, ConcealmentKey,
    ConcealmentProfile, CredentialRequest, CredentialResponse, NeedCredential,
    NeedIdentityPreparation, PendingAuthorization, PendingServerCredential, ProofResult, Server,
    ServerAuthenticated, ServerConfig, ServerConfigBuilder, ServerCredential,
};
