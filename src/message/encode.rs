//! Canonical bounded encoders for the four SCRAM message shapes.

use alloc::vec::Vec;

use crate::{
    ChannelBindingMode, IterationCount, OutboundMessage, PeerError, PreparedAuthenticationIdentity,
    PreparedAuthorizationIdentity, ProtocolError, ResourceLimits,
};

use super::{
    attribute::validate_nonce,
    base64::{append_encoded, encoded_len},
    encode_shared::{
        append_gs2_header, bounded_output, checked_sum, gs2_header_len,
        validate_outbound_authorization, validate_outbound_identity,
    },
    identity::{append_escaped, escaped_len},
};

/// Encodes a canonical client-first message without optional extensions.
pub fn encode_client_first(
    mode: &ChannelBindingMode,
    authentication_identity: &PreparedAuthenticationIdentity,
    authorization_identity: Option<&PreparedAuthorizationIdentity>,
    nonce: &[u8],
    limits: &ResourceLimits,
) -> Result<OutboundMessage, ProtocolError> {
    validate_outbound_identity(
        authentication_identity.as_str(),
        limits.max_identity_bytes(),
    )?;
    validate_outbound_authorization(authorization_identity, limits)?;
    validate_nonce(nonce, limits.max_nonce_bytes())?;
    let header_length = gs2_header_len(mode, authorization_identity)?;
    let identity_length = escaped_len(authentication_identity.as_str()).unwrap_or(usize::MAX);
    let length = checked_sum(&[header_length, 2, identity_length, 3, nonce.len()]);
    let mut output = bounded_output(length, limits)?;
    append_gs2_header(&mut output, mode, authorization_identity);
    output.extend_from_slice(b"n=");
    append_escaped(&mut output, authentication_identity.as_str());
    output.extend_from_slice(b",r=");
    output.extend_from_slice(nonce);
    Ok(OutboundMessage::new(output))
}

/// Encodes a canonical server-first message without optional extensions.
pub fn encode_server_first(
    nonce: &[u8],
    salt: &[u8],
    iterations: IterationCount,
    limits: &ResourceLimits,
) -> Result<OutboundMessage, ProtocolError> {
    validate_nonce(nonce, limits.max_nonce_bytes())?;
    if salt.len() > limits.max_salt_bytes() {
        return Err(ProtocolError::SaltTooLarge {
            length: salt.len(),
            maximum: limits.max_salt_bytes(),
        });
    }
    let salt_length = encoded_len(salt.len()).unwrap_or(usize::MAX);
    let digits = decimal_len(iterations.get());
    let length = checked_sum(&[2, nonce.len(), 3, salt_length, 3, digits]);
    let mut output = bounded_output(length, limits)?;
    output.extend_from_slice(b"r=");
    output.extend_from_slice(nonce);
    output.extend_from_slice(b",s=");
    append_encoded(&mut output, salt);
    output.extend_from_slice(b",i=");
    append_decimal(&mut output, iterations.get());
    Ok(OutboundMessage::new(output))
}

/// Encodes a canonical successful server-final verifier message.
pub fn encode_server_final_verifier(
    verifier: &[u8],
    limits: &ResourceLimits,
) -> Result<OutboundMessage, ProtocolError> {
    let verifier_length = encoded_len(verifier.len()).unwrap_or(usize::MAX);
    let length = checked_sum(&[2, verifier_length]);
    let mut output = bounded_output(length, limits)?;
    output.extend_from_slice(b"v=");
    append_encoded(&mut output, verifier);
    Ok(OutboundMessage::new(output))
}

/// Encodes a canonical server-final error from the bounded peer vocabulary.
pub fn encode_server_final_error(
    error: PeerError,
    limits: &ResourceLimits,
) -> Result<OutboundMessage, ProtocolError> {
    let value = peer_error_value(error);
    let length = checked_sum(&[2, value.len()]);
    let mut output = bounded_output(length, limits)?;
    output.extend_from_slice(b"e=");
    output.extend_from_slice(value);
    Ok(OutboundMessage::new(output))
}

fn decimal_len(mut value: u32) -> usize {
    let mut length = 1;
    while value >= 10 {
        value /= 10;
        length += 1;
    }
    length
}

fn append_decimal(output: &mut Vec<u8>, mut value: u32) {
    let mut digits = [0_u8; 10];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = decimal_digit(value % 10);
        value /= 10;
        if value == 0 {
            break;
        }
    }
    output.extend_from_slice(&digits[start..]);
}

const fn decimal_digit(value: u32) -> u8 {
    match value {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        _ => b'9',
    }
}

const fn peer_error_value(error: PeerError) -> &'static [u8] {
    match error {
        PeerError::InvalidEncoding => b"invalid-encoding",
        PeerError::ExtensionsNotSupported => b"extensions-not-supported",
        PeerError::InvalidProof => b"invalid-proof",
        PeerError::ChannelBindingsDoNotMatch => b"channel-bindings-dont-match",
        PeerError::ServerSupportsChannelBinding => b"server-does-support-channel-binding",
        PeerError::ChannelBindingNotSupported => b"channel-binding-not-supported",
        PeerError::UnsupportedChannelBindingType => b"unsupported-channel-binding-type",
        PeerError::UnknownUser => b"unknown-user",
        PeerError::InvalidUsernameEncoding => b"invalid-username-encoding",
        PeerError::NoResources => b"no-resources",
        PeerError::OtherError | PeerError::Other => b"other-error",
    }
}
