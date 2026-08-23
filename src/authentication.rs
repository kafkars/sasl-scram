//! Nonsecret security properties established by a completed SCRAM exchange.

use crate::{Algorithm, ChannelBindingName};

#[cfg(any(feature = "sha256", feature = "sha512"))]
use crate::ChannelBindingMode;

/// The channel-binding property authenticated by a successful exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChannelBindingOutcome {
    /// The authenticated exchange used the non-PLUS mechanism.
    Unbound,
    /// The authenticated exchange proved one named channel binding.
    Bound {
        /// The GS2 channel-binding name whose data was authenticated.
        name: ChannelBindingName,
    },
}

/// Nonsecret mechanism properties established by complete proof verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationProperties {
    algorithm: Algorithm,
    channel_binding: ChannelBindingOutcome,
}

impl AuthenticationProperties {
    #[cfg(any(feature = "sha256", feature = "sha512"))]
    pub(crate) fn from_mode(algorithm: Algorithm, mode: &ChannelBindingMode) -> Self {
        let channel_binding = match mode {
            ChannelBindingMode::Unsupported | ChannelBindingMode::AvailableButNotNegotiated => {
                ChannelBindingOutcome::Unbound
            }
            ChannelBindingMode::Required(binding) => ChannelBindingOutcome::Bound {
                name: binding.name().clone(),
            },
        };
        Self {
            algorithm,
            channel_binding,
        }
    }

    /// Returns the algorithm whose complete transcript was authenticated.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns whether channel binding was authenticated and its public name.
    pub const fn channel_binding(&self) -> &ChannelBindingOutcome {
        &self.channel_binding
    }
}
