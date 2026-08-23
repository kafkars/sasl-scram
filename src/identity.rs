//! Received and prepared identity values kept distinct across server policy.

use alloc::boxed::Box;
use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::PreparationError;

/// Authentication identity decoded from one client-first message, before preparation.
pub struct ReceivedAuthenticationIdentity(Box<str>);

impl ReceivedAuthenticationIdentity {
    #[cfg(any(feature = "sha256", feature = "sha512"))]
    pub(crate) const fn from_wire(value: Box<str>) -> Self {
        Self(value)
    }

    /// Borrows the decoded, unescaped identity exactly as received.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Zeroize for ReceivedAuthenticationIdentity {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for ReceivedAuthenticationIdentity {}

impl Drop for ReceivedAuthenticationIdentity {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for ReceivedAuthenticationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedAuthenticationIdentity")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Authorization identity decoded from one client-first message, before preparation.
pub struct ReceivedAuthorizationIdentity(Box<str>);

impl ReceivedAuthorizationIdentity {
    #[cfg(any(feature = "sha256", feature = "sha512"))]
    pub(crate) const fn from_wire(value: Box<str>) -> Self {
        Self(value)
    }

    /// Borrows the decoded, unescaped identity exactly as received.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Zeroize for ReceivedAuthorizationIdentity {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for ReceivedAuthorizationIdentity {}

impl Drop for ReceivedAuthorizationIdentity {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for ReceivedAuthorizationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedAuthorizationIdentity")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Authentication identity prepared by an explicit credential profile.
#[derive(Eq, PartialEq)]
pub struct PreparedAuthenticationIdentity(Box<str>);

impl PreparedAuthenticationIdentity {
    /// Accepts identity text already prepared by a documented protocol profile.
    pub fn from_protocol_profile(value: impl Into<Box<str>>) -> Result<Self, PreparationError> {
        let value = value.into();
        if value.is_empty() || value.as_bytes().contains(&0) {
            return Err(PreparationError::InvalidAuthenticationIdentity);
        }
        Ok(Self(value))
    }

    /// Borrows the prepared, unescaped identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Zeroize for PreparedAuthenticationIdentity {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for PreparedAuthenticationIdentity {}

impl Drop for PreparedAuthenticationIdentity {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for PreparedAuthenticationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAuthenticationIdentity")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Authorization identity prepared by an explicit credential profile.
#[derive(Eq, PartialEq)]
pub struct PreparedAuthorizationIdentity(Box<str>);

impl PreparedAuthorizationIdentity {
    /// Accepts identity text already prepared by a documented protocol profile.
    pub fn from_protocol_profile(value: impl Into<Box<str>>) -> Result<Self, PreparationError> {
        let value = value.into();
        if value.is_empty() || value.as_bytes().contains(&0) {
            return Err(PreparationError::InvalidAuthorizationIdentity);
        }
        Ok(Self(value))
    }

    /// Borrows the prepared, unescaped identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Zeroize for PreparedAuthorizationIdentity {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for PreparedAuthorizationIdentity {}

impl Drop for PreparedAuthorizationIdentity {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for PreparedAuthorizationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAuthorizationIdentity")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
