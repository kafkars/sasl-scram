//! Validated configuration for one client conversation.

use core::fmt;
use zeroize::ZeroizeOnDrop;

use crate::{
    Algorithm, ChannelBindingMode, ClientPolicy, PolicyError, PreparedAuthorizationIdentity,
    PreparedCredentials,
};

use super::CLIENT_NONCE_BYTES;

/// Owned configuration consumed by one SCRAM client conversation.
pub struct ClientConfig {
    pub(super) algorithm: Algorithm,
    pub(super) credentials: PreparedCredentials,
    pub(super) channel_binding: ChannelBindingMode,
    pub(super) policy: ClientPolicy,
}

impl ZeroizeOnDrop for ClientConfig {}

impl ClientConfig {
    /// Starts a builder for an explicit algorithm with unbound SCRAM and default limits.
    pub fn builder(algorithm: Algorithm) -> ClientConfigBuilder {
        ClientConfigBuilder {
            algorithm,
            credentials: None,
            channel_binding: ChannelBindingMode::Unsupported,
            policy: ClientPolicy::default(),
        }
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfig")
            .field("algorithm", &self.algorithm)
            .field("credentials", &"[REDACTED]")
            .field("channel_binding", &self.channel_binding)
            .field("policy", &self.policy)
            .finish()
    }
}

/// Consuming builder for one [`ClientConfig`].
#[must_use]
pub struct ClientConfigBuilder {
    algorithm: Algorithm,
    credentials: Option<PreparedCredentials>,
    channel_binding: ChannelBindingMode,
    policy: ClientPolicy,
}

impl ZeroizeOnDrop for ClientConfigBuilder {}

impl ClientConfigBuilder {
    /// Supplies credentials prepared exactly once by an explicit profile.
    pub fn credentials(mut self, credentials: PreparedCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Selects the GS2 channel-binding negotiation result.
    pub fn channel_binding(mut self, channel_binding: ChannelBindingMode) -> Self {
        self.channel_binding = channel_binding;
        self
    }

    /// Supplies client-side resource and derivation policy.
    pub const fn policy(mut self, policy: ClientPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Validates the algorithm, credentials, binding, and complete-message capacity.
    pub fn build(self) -> Result<ClientConfig, PolicyError> {
        let Some(proof_bytes) = self.algorithm.output_len() else {
            return Err(PolicyError::AlgorithmNotPermitted);
        };
        if let ChannelBindingMode::Required(binding) = &self.channel_binding {
            let maximum = self.policy.resources().max_channel_binding_bytes();
            if binding.data().len() > maximum {
                return Err(PolicyError::ChannelBindingTooLarge {
                    length: binding.data().len(),
                    maximum,
                });
            }
        }
        let Some(credentials) = self.credentials else {
            return Err(PolicyError::MissingCredentials);
        };
        let (binding_name_bytes, binding_data_bytes) = match &self.channel_binding {
            ChannelBindingMode::Required(binding) => {
                (binding.name().as_str().len(), binding.data().len())
            }
            ChannelBindingMode::Unsupported | ChannelBindingMode::AvailableButNotNegotiated => {
                (0, 0)
            }
        };
        let resources = self.policy.resources();
        let authentication_identity = credentials.authentication_identity();
        let authentication_length = authentication_identity.as_str().len();
        let maximum_authentication = resources.max_identity_bytes();
        if authentication_length > maximum_authentication {
            return Err(PolicyError::AuthenticationIdentityTooLong {
                length: authentication_length,
                maximum: maximum_authentication,
            });
        }
        let authorization_identity = credentials.authorization_identity();
        if let Some(identity) = authorization_identity {
            let length = identity.as_str().len();
            let maximum = resources.max_authorization_identity_bytes();
            if length > maximum {
                return Err(PolicyError::AuthorizationIdentityTooLong { length, maximum });
            }
        }
        resources.validate_client_first_capacity(
            binding_name_bytes,
            authentication_identity.as_str(),
            authorization_identity.map(PreparedAuthorizationIdentity::as_str),
            CLIENT_NONCE_BYTES,
        )?;
        self.policy.resources().validate_client_final_capacity(
            binding_name_bytes,
            binding_data_bytes,
            authorization_identity.map_or(0, |identity| identity.as_str().len()),
            authorization_identity.is_some(),
            proof_bytes,
        )?;
        Ok(ClientConfig {
            algorithm: self.algorithm,
            credentials,
            channel_binding: self.channel_binding,
            policy: self.policy,
        })
    }
}

impl fmt::Debug for ClientConfigBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfigBuilder")
            .field("algorithm", &self.algorithm)
            .field("has_credentials", &self.credentials.is_some())
            .field("channel_binding", &self.channel_binding)
            .field("policy", &self.policy)
            .finish()
    }
}
