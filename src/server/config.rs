//! Validated configuration for one server conversation.

use core::fmt;
use zeroize::ZeroizeOnDrop;

use crate::{Algorithm, ChannelBindingMode, PolicyError, ServerPolicy};

/// Owned, secret-free configuration consumed by one server conversation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub(super) algorithm: Algorithm,
    pub(super) policy: ServerPolicy,
}

impl ServerConfig {
    /// Starts a builder for an explicit algorithm with unbound SCRAM and default limits.
    pub fn builder(algorithm: Algorithm) -> ServerConfigBuilder {
        ServerConfigBuilder {
            algorithm,
            policy: ServerPolicy::default(),
        }
    }
}

/// Consuming builder for one [`ServerConfig`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct ServerConfigBuilder {
    algorithm: Algorithm,
    policy: ServerPolicy,
}

impl ServerConfigBuilder {
    /// Supplies server-side resource and credential policy.
    pub const fn policy(mut self, policy: ServerPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Validates the algorithm and unbound complete-message capacity.
    pub fn build(self) -> Result<ServerConfig, PolicyError> {
        let Some(proof_bytes) = self.algorithm.output_len() else {
            return Err(PolicyError::AlgorithmNotPermitted);
        };
        let resources = self.policy.resources();
        resources.validate_client_final_capacity(
            0,
            0,
            resources.max_authorization_identity_bytes(),
            true,
            proof_bytes,
        )?;
        Ok(ServerConfig {
            algorithm: self.algorithm,
            policy: self.policy,
        })
    }
}

/// One configured namespace value consumed to begin a server conversation.
pub struct Server {
    pub(super) config: ServerConfig,
    pub(super) channel_binding: ChannelBindingMode,
}

impl Server {
    /// Creates one unbound server conversation endpoint without performing I/O.
    pub const fn new(config: ServerConfig) -> Self {
        Self {
            config,
            channel_binding: ChannelBindingMode::Unsupported,
        }
    }

    /// Creates one server endpoint for an explicit channel-binding result that
    /// fits the configured complete-message capacity.
    pub fn with_channel_binding(
        config: ServerConfig,
        channel_binding: ChannelBindingMode,
    ) -> Result<Self, PolicyError> {
        let Some(proof_bytes) = config.algorithm.output_len() else {
            return Err(PolicyError::AlgorithmNotPermitted);
        };
        if let ChannelBindingMode::Required(binding) = &channel_binding {
            let resources = config.policy.resources();
            let maximum = resources.max_channel_binding_bytes();
            if binding.data().len() > maximum {
                return Err(PolicyError::ChannelBindingTooLarge {
                    length: binding.data().len(),
                    maximum,
                });
            }
            resources.validate_client_final_capacity(
                binding.name().as_str().len(),
                binding.data().len(),
                resources.max_authorization_identity_bytes(),
                true,
                proof_bytes,
            )?;
        }
        Ok(Self {
            config,
            channel_binding,
        })
    }
}

impl ZeroizeOnDrop for Server {}

impl fmt::Debug for Server {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Server")
            .field("algorithm", &self.config.algorithm)
            .field("channel_binding", &self.channel_binding)
            .field("policy", &self.config.policy)
            .finish()
    }
}
