//! Client-first validation and the caller-owned credential lookup continuation.

use alloc::vec::Vec;
use core::fmt;

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    Algorithm, ChannelBindingMode, ConcealmentKey, ConcealmentProfile, CredentialResponse, Error,
    NonceSource, OutboundMessage, PolicyError, PreparedAuthenticationIdentity,
    PreparedAuthorizationIdentity, ProtocolError, SecretBytes, ServerPolicy,
    message::encode_server_first,
};

use super::AwaitingClientFinal;

const NONCE_ENTROPY_BYTES: usize = 15;
const ENCODED_NONCE_BYTES: usize = 20;

/// Borrowed identity request for an application credential store.
#[derive(Clone, Copy)]
pub struct CredentialRequest<'a> {
    authentication_identity: &'a PreparedAuthenticationIdentity,
    authorization_identity: Option<&'a PreparedAuthorizationIdentity>,
}

impl<'a> CredentialRequest<'a> {
    /// Returns the prepared authentication identity to look up.
    pub const fn authentication_identity(self) -> &'a PreparedAuthenticationIdentity {
        self.authentication_identity
    }

    /// Returns the optional requested authorization identity.
    pub const fn authorization_identity(self) -> Option<&'a PreparedAuthorizationIdentity> {
        self.authorization_identity
    }
}

impl fmt::Debug for CredentialRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRequest")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// One parsed client-first message awaiting caller-owned credential lookup.
///
/// The continuation owns the exact transcript, so it may cross an async lookup
/// boundary without borrowing the transport input.
///
/// ```compile_fail
/// fn resume_twice<N: sasl_scram::NonceSource>(
///     state: sasl_scram::NeedCredential,
///     first: sasl_scram::CredentialResponse<()>,
///     second: sasl_scram::CredentialResponse<()>,
///     nonce: &mut N,
/// ) {
///     let _first = state.resume(first, nonce);
///     let _second = state.resume(second, nonce);
/// }
/// ```
pub struct NeedCredential {
    pub(super) algorithm: Algorithm,
    pub(super) channel_binding: ChannelBindingMode,
    pub(super) policy: ServerPolicy,
    pub(super) authentication_identity: PreparedAuthenticationIdentity,
    pub(super) authorization_identity: Option<PreparedAuthorizationIdentity>,
    pub(super) gs2_header: SecretBytes,
    pub(super) client_first_bare: SecretBytes,
    pub(super) client_nonce: SecretBytes,
}

impl ZeroizeOnDrop for NeedCredential {}

impl NeedCredential {
    /// Borrows the bounded identity lookup request without defining a store trait.
    pub const fn credential_request(&self) -> CredentialRequest<'_> {
        CredentialRequest {
            authentication_identity: &self.authentication_identity,
            authorization_identity: self.authorization_identity.as_ref(),
        }
    }

    /// Builds a synthetic lookup response bound to this exact credential request.
    pub fn conceal<P>(
        &self,
        key: &ConcealmentKey,
        profile: ConcealmentProfile,
    ) -> Result<CredentialResponse<P>, Error> {
        let salt_length = profile.salt_bytes().get();
        if salt_length > self.policy.resources().max_salt_bytes() {
            return Err(ProtocolError::SaltTooLarge {
                length: salt_length,
                maximum: self.policy.resources().max_salt_bytes(),
            }
            .into());
        }
        self.policy.salt().validate(salt_length)?;
        self.policy.iterations().validate(profile.iterations())?;
        let synthetic =
            key.derive_credential(self.algorithm, &self.authentication_identity, profile)?;
        Ok(CredentialResponse::Concealed { synthetic })
    }

    /// Resumes with a known or concealed verifier and emits one server-first message.
    pub fn resume<P>(
        self,
        response: CredentialResponse<P>,
        nonce_source: &mut impl NonceSource,
    ) -> Result<(AwaitingClientFinal<P>, OutboundMessage), Error> {
        let Self {
            algorithm,
            channel_binding,
            policy,
            authentication_identity,
            authorization_identity,
            gs2_header,
            client_first_bare,
            client_nonce,
        } = self;
        let (principal, credential) = match response {
            CredentialResponse::Known {
                principal,
                credential,
            } => (Some(principal), credential),
            CredentialResponse::Concealed { synthetic } => (None, synthetic),
        };
        if credential.algorithm() != algorithm {
            return Err(PolicyError::InvalidCredential.into());
        }
        credential.validate(policy)?;
        let maximum = policy.resources().max_nonce_bytes();
        let combined_length = client_nonce.len().saturating_add(ENCODED_NONCE_BYTES);
        if combined_length > maximum {
            return Err(ProtocolError::NonceTooLarge {
                length: combined_length,
                maximum,
            }
            .into());
        }
        let mut entropy = Zeroizing::new([0_u8; NONCE_ENTROPY_BYTES]);
        nonce_source.fill(entropy.as_mut())?;
        let suffix = crate::message::encode_base64(entropy.as_ref());
        let mut combined_nonce = Zeroizing::new(Vec::with_capacity(combined_length));
        combined_nonce.extend_from_slice(client_nonce.expose_secret());
        combined_nonce.extend_from_slice(&suffix);
        let server_first = encode_server_first(
            &combined_nonce,
            credential.salt().expose_bytes(),
            credential.iterations(),
            &policy.resources(),
        )?;
        let state = AwaitingClientFinal {
            algorithm,
            channel_binding,
            policy,
            authentication_identity,
            authorization_identity,
            gs2_header,
            client_first_bare,
            server_first: SecretBytes::new(server_first.as_bytes()),
            combined_nonce: SecretBytes::new(combined_nonce.as_slice()),
            credential,
            principal,
        };
        Ok((state, server_first))
    }
}

impl fmt::Debug for NeedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeedCredential")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
