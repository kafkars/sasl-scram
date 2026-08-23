//! Resource and iteration policies kept distinct from protocol syntax.

use core::num::NonZeroU32;

use crate::PolicyError;

mod capacity;

/// A positive iteration count parsed from a SCRAM challenge or credential.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IterationCount(NonZeroU32);

impl IterationCount {
    /// Creates a positive iteration count.
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    /// Returns the underlying positive integer.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Credential-strength and denial-of-service bounds for derivation work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IterationPolicy {
    minimum: NonZeroU32,
    maximum: NonZeroU32,
}

impl IterationPolicy {
    /// Creates a policy when the minimum does not exceed the maximum.
    pub const fn new(minimum: NonZeroU32, maximum: NonZeroU32) -> Result<Self, PolicyError> {
        if minimum.get() > maximum.get() {
            return Err(PolicyError::InvalidResourceLimit);
        }
        Ok(Self { minimum, maximum })
    }

    /// Returns the minimum accepted iteration count.
    pub const fn minimum(self) -> NonZeroU32 {
        self.minimum
    }

    /// Returns the maximum accepted iteration count.
    pub const fn maximum(self) -> NonZeroU32 {
        self.maximum
    }

    /// Validates a parsed count against both bounds.
    pub const fn validate(self, count: IterationCount) -> Result<(), PolicyError> {
        if count.get() < self.minimum.get() {
            return Err(PolicyError::IterationCountTooLow);
        }
        if count.get() > self.maximum.get() {
            return Err(PolicyError::IterationCountTooHigh);
        }
        Ok(())
    }
}

impl Default for IterationPolicy {
    fn default() -> Self {
        Self {
            minimum: NonZeroU32::MIN.saturating_add(4095),
            maximum: NonZeroU32::MIN.saturating_add(999_999),
        }
    }
}

/// Bounds for attacker-controlled message structure and decoded values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    max_message_bytes: usize,
    max_attributes: usize,
    max_identity_bytes: usize,
    max_authorization_identity_bytes: usize,
    max_nonce_bytes: usize,
    max_salt_bytes: usize,
    max_channel_binding_bytes: usize,
    max_extension_bytes: usize,
}

impl ResourceLimits {
    /// Starts a resource-limit builder with conservative defaults.
    pub const fn builder() -> ResourceLimitsBuilder {
        ResourceLimitsBuilder::new()
    }

    /// Returns the maximum complete message length.
    pub const fn max_message_bytes(self) -> usize {
        self.max_message_bytes
    }

    /// Returns the maximum number of comma-separated attributes.
    pub const fn max_attributes(self) -> usize {
        self.max_attributes
    }

    /// Returns the maximum decoded authentication-identity length.
    pub const fn max_identity_bytes(self) -> usize {
        self.max_identity_bytes
    }

    /// Returns the maximum decoded authorization-identity length.
    pub const fn max_authorization_identity_bytes(self) -> usize {
        self.max_authorization_identity_bytes
    }

    /// Returns the maximum nonce length.
    pub const fn max_nonce_bytes(self) -> usize {
        self.max_nonce_bytes
    }

    /// Returns the maximum decoded salt length.
    pub const fn max_salt_bytes(self) -> usize {
        self.max_salt_bytes
    }

    /// Returns the maximum decoded channel-binding length.
    pub const fn max_channel_binding_bytes(self) -> usize {
        self.max_channel_binding_bytes
    }

    /// Returns the maximum encoded optional-extension region length.
    pub const fn max_extension_bytes(self) -> usize {
        self.max_extension_bytes
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimitsBuilder::new().finish()
    }
}

/// A consuming builder for [`ResourceLimits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct ResourceLimitsBuilder(ResourceLimits);

impl ResourceLimitsBuilder {
    const fn new() -> Self {
        Self(ResourceLimits {
            max_message_bytes: 16 * 1024,
            max_attributes: 32,
            max_identity_bytes: 1024,
            max_authorization_identity_bytes: 1024,
            max_nonce_bytes: 1024,
            max_salt_bytes: 1024,
            max_channel_binding_bytes: 8 * 1024,
            max_extension_bytes: 4096,
        })
    }

    /// Sets the complete-message byte limit.
    pub const fn max_message_bytes(mut self, value: usize) -> Self {
        self.0.max_message_bytes = value;
        self
    }

    /// Sets the attribute-count limit.
    pub const fn max_attributes(mut self, value: usize) -> Self {
        self.0.max_attributes = value;
        self
    }

    /// Sets the decoded authentication-identity limit.
    pub const fn max_identity_bytes(mut self, value: usize) -> Self {
        self.0.max_identity_bytes = value;
        self
    }

    /// Sets the decoded authorization-identity limit.
    pub const fn max_authorization_identity_bytes(mut self, value: usize) -> Self {
        self.0.max_authorization_identity_bytes = value;
        self
    }

    /// Sets the nonce byte limit.
    pub const fn max_nonce_bytes(mut self, value: usize) -> Self {
        self.0.max_nonce_bytes = value;
        self
    }

    /// Sets the decoded salt limit.
    pub const fn max_salt_bytes(mut self, value: usize) -> Self {
        self.0.max_salt_bytes = value;
        self
    }

    /// Sets the decoded channel-binding limit.
    pub const fn max_channel_binding_bytes(mut self, value: usize) -> Self {
        self.0.max_channel_binding_bytes = value;
        self
    }

    /// Sets the encoded optional-extension region limit.
    pub const fn max_extension_bytes(mut self, value: usize) -> Self {
        self.0.max_extension_bytes = value;
        self
    }

    /// Validates nonzero limits and verifies that the maximum binding payload
    /// can fit inside a structurally complete client-final message.
    pub fn build(self) -> Result<ResourceLimits, PolicyError> {
        let limits = self.0;
        if limits.max_message_bytes == 0
            || limits.max_attributes == 0
            || limits.max_identity_bytes == 0
            || limits.max_authorization_identity_bytes == 0
            || limits.max_nonce_bytes == 0
            || limits.max_salt_bytes == 0
            || limits.max_channel_binding_bytes == 0
            || limits.max_extension_bytes == 0
        {
            return Err(PolicyError::InvalidResourceLimit);
        }
        if !capacity::maximum_binding_fits(limits) {
            return Err(PolicyError::InvalidResourceLimit);
        }
        Ok(limits)
    }

    const fn finish(self) -> ResourceLimits {
        self.0
    }
}
