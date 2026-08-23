//! Borrowed SCRAM message views that preserve exact authenticated fragments.

mod attribute;
mod base64;
mod client_final;
mod client_final_outbound;
mod client_first;
mod encode;
mod encode_shared;
mod extensions;
mod identity;
mod server_final;
mod server_first;
mod transcript;

#[cfg(any(feature = "sha256", feature = "sha512"))]
pub(crate) use base64::{decode_owned as decode_base64, encode_owned as encode_base64};

pub use client_final::ClientFinal;
pub use client_final_outbound::{
    ClientFinalWithoutProof, encode_client_final, encode_client_final_without_proof,
};
pub use client_first::{ClientFirst, Gs2Flag};
pub use encode::{
    encode_client_first, encode_server_final_error, encode_server_final_verifier,
    encode_server_first,
};
pub use extensions::Extensions;
pub use server_final::{ServerFinal, ServerFinalOutcome, ServerVerifier};
pub use server_first::ServerFirst;
pub use transcript::AuthenticationTranscript;
