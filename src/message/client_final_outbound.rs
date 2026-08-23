//! Two-stage client-final encoding around the proof-derivation boundary.

use alloc::vec::Vec;
use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    ChannelBindingMode, OutboundMessage, PreparedAuthorizationIdentity, ProtocolError,
    ResourceLimits,
};

use super::{
    attribute::validate_nonce,
    base64::{append_encoded, encoded_len},
    encode_shared::{
        append_gs2_header, binding_data, bounded_output, checked_sum, gs2_header_len,
        validate_outbound_authorization,
    },
};

/// An exact client-final transcript fragment awaiting its derived proof.
pub struct ClientFinalWithoutProof {
    bytes: OutboundMessage,
}

impl ClientFinalWithoutProof {
    /// Explicitly borrows the exact `client-final-message-without-proof` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }

    /// Appends the canonical Base64 proof and consumes the transcript fragment.
    pub fn finish(
        self,
        proof: &[u8],
        limits: &ResourceLimits,
    ) -> Result<OutboundMessage, ProtocolError> {
        let length = self.finished_length(proof.len());
        let mut output = bounded_output(length, limits)?;
        output.extend_from_slice(self.as_bytes());
        output.extend_from_slice(b",p=");
        append_encoded(&mut output, proof);
        Ok(OutboundMessage::new(output))
    }

    #[cfg(any(feature = "sha256", feature = "sha512"))]
    pub(crate) fn validate_proof_length(
        &self,
        proof_length: usize,
        limits: &ResourceLimits,
    ) -> Result<(), ProtocolError> {
        bounded_output(self.finished_length(proof_length), limits).map(|_| ())
    }

    fn finished_length(&self, proof_length: usize) -> usize {
        let proof_base64 = encoded_len(proof_length).unwrap_or(usize::MAX);
        checked_sum(&[self.as_bytes().len(), 3, proof_base64])
    }
}

impl Zeroize for ClientFinalWithoutProof {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for ClientFinalWithoutProof {}

impl fmt::Debug for ClientFinalWithoutProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientFinalWithoutProof")
            .field("length", &self.bytes.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Encodes the authenticated client-final fragment before expensive proof derivation.
pub fn encode_client_final_without_proof(
    mode: &ChannelBindingMode,
    authorization_identity: Option<&PreparedAuthorizationIdentity>,
    nonce: &[u8],
    limits: &ResourceLimits,
) -> Result<ClientFinalWithoutProof, ProtocolError> {
    validate_outbound_authorization(authorization_identity, limits)?;
    validate_nonce(nonce, limits.max_nonce_bytes())?;
    let header_length = gs2_header_len(mode, authorization_identity)?;
    let binding = binding_data(mode, limits)?;
    let input_length = checked_sum(&[header_length, binding.len()]);
    let binding_base64 = encoded_len(input_length).unwrap_or(usize::MAX);
    let length = checked_sum(&[2, binding_base64, 3, nonce.len()]);
    let mut output = bounded_output(length, limits)?;
    output.extend_from_slice(b"c=");
    let mut input = Zeroizing::new(Vec::with_capacity(input_length));
    append_gs2_header(&mut input, mode, authorization_identity);
    input.extend_from_slice(binding);
    append_encoded(&mut output, &input);
    output.extend_from_slice(b",r=");
    output.extend_from_slice(nonce);
    Ok(ClientFinalWithoutProof {
        bytes: OutboundMessage::new(output),
    })
}

/// Encodes a canonical client-final message when the proof is already available.
pub fn encode_client_final(
    mode: &ChannelBindingMode,
    authorization_identity: Option<&PreparedAuthorizationIdentity>,
    nonce: &[u8],
    proof: &[u8],
    limits: &ResourceLimits,
) -> Result<OutboundMessage, ProtocolError> {
    encode_client_final_without_proof(mode, authorization_identity, nonce, limits)?
        .finish(proof, limits)
}
