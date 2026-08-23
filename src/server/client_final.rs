//! Client-final validation and constant-time proof verification.

use core::fmt;

use crate::{
    Algorithm, AuthenticationProperties, ChannelBindingMode, Error, OutboundMessage, PeerError,
    PolicyError, PreparedAuthenticationIdentity, PreparedAuthorizationIdentity, ProtocolError,
    SecretBytes, ServerCredential, ServerPolicy,
    message::{AuthenticationTranscript, ClientFinal, decode_base64, encode_server_final_error},
};

use super::PendingAuthorization;

/// Server state that accepts exactly one client-final message.
pub struct AwaitingClientFinal<P> {
    pub(super) algorithm: Algorithm,
    pub(super) channel_binding: ChannelBindingMode,
    pub(super) policy: ServerPolicy,
    pub(super) authentication_identity: PreparedAuthenticationIdentity,
    pub(super) authorization_identity: Option<PreparedAuthorizationIdentity>,
    pub(super) gs2_header: SecretBytes,
    pub(super) client_first_bare: SecretBytes,
    pub(super) server_first: SecretBytes,
    pub(super) combined_nonce: SecretBytes,
    pub(super) credential: ServerCredential,
    pub(super) principal: Option<P>,
}

impl<P> AwaitingClientFinal<P> {
    /// Verifies one proof and returns either authorization work or a wire rejection.
    ///
    /// ```compile_fail
    /// fn receive_twice(state: sasl_scram::AwaitingClientFinal<()>, message: &[u8]) {
    ///     let _first = state.receive_client_final(message);
    ///     let _second = state.receive_client_final(message);
    /// }
    /// ```
    pub fn receive_client_final(self, input: &[u8]) -> Result<ProofResult<P>, Error> {
        let Self {
            algorithm,
            channel_binding: expected_channel_binding,
            policy,
            authentication_identity,
            authorization_identity,
            gs2_header,
            client_first_bare,
            server_first,
            combined_nonce,
            credential,
            principal,
        } = self;
        let parsed = ClientFinal::parse(input, &policy.resources())?;
        if parsed.nonce() != combined_nonce.expose_secret() {
            return Err(ProtocolError::InvalidNonce.into());
        }
        let channel_binding =
            SecretBytes::new(decode_base64(parsed.channel_binding_base64())?.into_boxed_slice());
        let payload_length = channel_binding.len().saturating_sub(gs2_header.len());
        let maximum_binding = policy.resources().max_channel_binding_bytes();
        if channel_binding.len() > gs2_header.len().saturating_add(maximum_binding) {
            return Err(ProtocolError::ChannelBindingTooLarge {
                length: payload_length,
                maximum: maximum_binding,
            }
            .into());
        }
        let binding_data = match &expected_channel_binding {
            ChannelBindingMode::Required(binding) => binding.data().expose_secret(),
            ChannelBindingMode::Unsupported | ChannelBindingMode::AvailableButNotNegotiated => &[],
        };
        if !crate::crypto::verify_channel_binding(
            gs2_header.expose_secret(),
            binding_data,
            channel_binding.expose_secret(),
        ) {
            return reject(PeerError::ChannelBindingsDoNotMatch, policy);
        }
        let properties = AuthenticationProperties::from_mode(algorithm, &expected_channel_binding);
        let proof = SecretBytes::new(decode_base64(parsed.proof_base64())?.into_boxed_slice());
        let output_len = algorithm
            .output_len()
            .ok_or(PolicyError::AlgorithmNotPermitted)?;
        if proof.len() != output_len {
            return reject(PeerError::InvalidProof, policy);
        }
        let auth_message = AuthenticationTranscript::from_fragments(
            client_first_bare.expose_secret(),
            server_first.expose_secret(),
            parsed.without_proof(),
        )
        .to_owned_message(&policy.resources())?;
        let verification = crate::crypto::verify_client_proof(
            algorithm,
            credential.stored_key.expose_secret(),
            credential.server_key.expose_secret(),
            auth_message.as_bytes(),
            proof.expose_secret(),
        )?;
        if !verification.is_valid() {
            return reject(PeerError::InvalidProof, policy);
        }
        let Some(principal) = principal else {
            return reject(PeerError::InvalidProof, policy);
        };
        Ok(ProofResult::Verified(PendingAuthorization {
            properties,
            policy,
            authentication_identity,
            authorization_identity,
            principal,
            server_signature: verification.into_server_signature(),
        }))
    }
}

impl<P> fmt::Debug for AwaitingClientFinal<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwaitingClientFinal")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Result of complete client-proof processing.
#[non_exhaustive]
pub enum ProofResult<P> {
    /// The proof is valid for a known identity and awaits authorization.
    Verified(PendingAuthorization<P>),
    /// The proof or concealed identity was rejected with a safe wire response.
    Rejected {
        /// Server-final error to send to the peer.
        server_final: OutboundMessage,
    },
}

impl<P> fmt::Debug for ProofResult<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofResult")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

fn reject<P>(error: PeerError, policy: ServerPolicy) -> Result<ProofResult<P>, Error> {
    Ok(ProofResult::Rejected {
        server_final: encode_server_final_error(error, &policy.resources())?,
    })
}
