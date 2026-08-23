//! Public policy aggregates for consuming client and server state machines.

use crate::{IterationPolicy, ResourceLimits, SaltPolicy};

/// Client-side limits and derivation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientPolicy {
    resources: ResourceLimits,
    iterations: IterationPolicy,
    salt: SaltPolicy,
}

impl ClientPolicy {
    /// Creates a policy from independently selected resource and iteration limits.
    pub const fn new(resources: ResourceLimits, iterations: IterationPolicy) -> Self {
        Self {
            resources,
            iterations,
            salt: SaltPolicy::client_default(),
        }
    }

    /// Replaces the default compatibility salt bounds with an explicit policy.
    #[must_use]
    pub const fn with_salt_policy(mut self, salt: SaltPolicy) -> Self {
        self.salt = salt;
        self
    }

    /// Returns resource limits.
    pub const fn resources(self) -> ResourceLimits {
        self.resources
    }

    /// Returns derivation iteration policy.
    pub const fn iterations(self) -> IterationPolicy {
        self.iterations
    }

    /// Returns accepted decoded salt-length bounds.
    pub const fn salt(self) -> SaltPolicy {
        self.salt
    }
}

impl Default for ClientPolicy {
    fn default() -> Self {
        Self::new(ResourceLimits::default(), IterationPolicy::default())
    }
}

/// Server-side limits and credential iteration policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerPolicy {
    resources: ResourceLimits,
    iterations: IterationPolicy,
    salt: SaltPolicy,
}

impl ServerPolicy {
    /// Creates a policy from independently selected resource and iteration limits.
    pub const fn new(resources: ResourceLimits, iterations: IterationPolicy) -> Self {
        Self {
            resources,
            iterations,
            salt: SaltPolicy::server_default(),
        }
    }

    /// Replaces the default server-record salt bounds with an explicit policy.
    #[must_use]
    pub const fn with_salt_policy(mut self, salt: SaltPolicy) -> Self {
        self.salt = salt;
        self
    }

    /// Returns resource limits.
    pub const fn resources(self) -> ResourceLimits {
        self.resources
    }

    /// Returns accepted credential iteration bounds.
    pub const fn iterations(self) -> IterationPolicy {
        self.iterations
    }

    /// Returns accepted verifier salt-length bounds.
    pub const fn salt(self) -> SaltPolicy {
        self.salt
    }
}

impl Default for ServerPolicy {
    fn default() -> Self {
        Self::new(ResourceLimits::default(), IterationPolicy::default())
    }
}
