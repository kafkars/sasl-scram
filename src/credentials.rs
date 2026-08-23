//! Prepared password and credential bundles accepted by SCRAM client states.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{PreparedAuthenticationIdentity, PreparedAuthorizationIdentity, SecretBytes};

/// Password bytes that have already passed one explicit preparation profile.
pub struct PreparedPassword(SecretBytes);

impl PreparedPassword {
    /// Accepts password bytes already prepared by a documented protocol profile.
    pub fn from_protocol_profile(value: SecretBytes) -> Self {
        Self(value)
    }

    /// Explicitly borrows the prepared password bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Returns the password length without exposing its contents.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the prepared password is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Zeroize for PreparedPassword {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for PreparedPassword {}

impl fmt::Debug for PreparedPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPassword")
            .field("length", &self.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Credentials prepared exactly once for consumption by the SCRAM core.
pub struct PreparedCredentials {
    authentication_identity: PreparedAuthenticationIdentity,
    authorization_identity: Option<PreparedAuthorizationIdentity>,
    password: PreparedPassword,
}

impl PreparedCredentials {
    /// Constructs credentials prepared by an explicitly documented protocol profile.
    pub fn from_protocol_profile(
        authentication_identity: PreparedAuthenticationIdentity,
        authorization_identity: Option<PreparedAuthorizationIdentity>,
        password: PreparedPassword,
    ) -> Self {
        Self {
            authentication_identity,
            authorization_identity,
            password,
        }
    }

    /// Returns the prepared authentication identity.
    pub const fn authentication_identity(&self) -> &PreparedAuthenticationIdentity {
        &self.authentication_identity
    }

    /// Returns the optional prepared authorization identity.
    pub const fn authorization_identity(&self) -> Option<&PreparedAuthorizationIdentity> {
        self.authorization_identity.as_ref()
    }

    /// Explicitly returns the prepared secret password.
    pub const fn password(&self) -> &PreparedPassword {
        &self.password
    }

    #[cfg(any(feature = "sha256", feature = "sha512"))]
    pub(crate) fn into_password(self) -> PreparedPassword {
        self.password
    }
}

impl Zeroize for PreparedCredentials {
    fn zeroize(&mut self) {
        self.authentication_identity.zeroize();
        if let Some(identity) = &mut self.authorization_identity {
            identity.zeroize();
        }
        self.password.zeroize();
    }
}

impl ZeroizeOnDrop for PreparedCredentials {}

impl fmt::Debug for PreparedCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCredentials")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
