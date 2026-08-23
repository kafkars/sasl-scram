//! Validated salt ownership and application-selected length policy.

use core::{fmt, num::NonZeroUsize};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{PolicyError, SecretBytes};

const DEFAULT_MINIMUM_SALT_BYTES: usize = 16;
const DEFAULT_MAXIMUM_SALT_BYTES: usize = 1024;

/// Credential-strength bounds for decoded salt bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SaltPolicy {
    minimum_bytes: NonZeroUsize,
    maximum_bytes: NonZeroUsize,
}

impl SaltPolicy {
    /// Creates a policy when the minimum does not exceed the maximum.
    pub const fn new(
        minimum_bytes: NonZeroUsize,
        maximum_bytes: NonZeroUsize,
    ) -> Result<Self, PolicyError> {
        if minimum_bytes.get() > maximum_bytes.get() {
            return Err(PolicyError::InvalidResourceLimit);
        }
        Ok(Self {
            minimum_bytes,
            maximum_bytes,
        })
    }

    pub(crate) const fn client_default() -> Self {
        Self {
            minimum_bytes: NonZeroUsize::MIN,
            maximum_bytes: NonZeroUsize::MIN.saturating_add(DEFAULT_MAXIMUM_SALT_BYTES - 1),
        }
    }

    pub(crate) const fn server_default() -> Self {
        Self {
            minimum_bytes: NonZeroUsize::MIN.saturating_add(DEFAULT_MINIMUM_SALT_BYTES - 1),
            maximum_bytes: NonZeroUsize::MIN.saturating_add(DEFAULT_MAXIMUM_SALT_BYTES - 1),
        }
    }

    /// Returns the minimum accepted decoded salt length.
    pub const fn minimum_bytes(self) -> NonZeroUsize {
        self.minimum_bytes
    }

    /// Returns the maximum accepted decoded salt length.
    pub const fn maximum_bytes(self) -> NonZeroUsize {
        self.maximum_bytes
    }

    /// Validates one decoded salt length.
    pub const fn validate(self, length: usize) -> Result<(), PolicyError> {
        if length < self.minimum_bytes.get() {
            return Err(PolicyError::SaltTooShort {
                length,
                minimum: self.minimum_bytes.get(),
            });
        }
        if length > self.maximum_bytes.get() {
            return Err(PolicyError::SaltTooLong {
                length,
                maximum: self.maximum_bytes.get(),
            });
        }
        Ok(())
    }
}

impl Default for SaltPolicy {
    fn default() -> Self {
        Self::server_default()
    }
}

/// Owned salt paired with a server verifier record.
pub struct Salt(SecretBytes);

impl Salt {
    /// Validates salt bytes against the default server-record policy.
    pub fn new(bytes: SecretBytes) -> Result<Self, PolicyError> {
        Self::with_policy(bytes, SaltPolicy::default())
    }

    /// Validates salt bytes against an explicit application profile.
    pub fn with_policy(bytes: SecretBytes, policy: SaltPolicy) -> Result<Self, PolicyError> {
        policy.validate(bytes.len())?;
        Ok(Self(bytes))
    }

    /// Explicitly borrows salt bytes for storage codecs.
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Returns the salt length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the salt is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Zeroize for Salt {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Salt {}

impl fmt::Debug for Salt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Salt")
            .field("length", &self.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
