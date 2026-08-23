//! Private cryptographic facade and constant-time verification.

mod dispatch;
#[cfg(feature = "sha256")]
mod sha256;
#[cfg(feature = "sha512")]
mod sha512;
mod verify;

pub(crate) use dispatch::{
    derive_client, derive_server_credential, derive_synthetic_credential, verify_client_proof,
};

pub(crate) fn verify_server_signature(expected: &[u8], received: &[u8]) -> bool {
    verify::constant_time_eq(expected, received)
}

pub(crate) fn verify_channel_binding(
    gs2_header: &[u8],
    binding_data: &[u8],
    received: &[u8],
) -> bool {
    let Some(expected_length) = gs2_header.len().checked_add(binding_data.len()) else {
        return false;
    };
    if received.len() != expected_length {
        return false;
    }
    let (received_header, received_data) = received.split_at(gs2_header.len());
    verify::constant_time_eq(gs2_header, received_header)
        & verify::constant_time_eq(binding_data, received_data)
}
