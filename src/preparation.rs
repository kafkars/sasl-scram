//! Explicit built-in credential-preparation profiles.

use crate::{
    PreparationError, PreparedAuthenticationIdentity, PreparedAuthorizationIdentity,
    PreparedCredentials, PreparedPassword, ReceivedAuthenticationIdentity,
    ReceivedAuthorizationIdentity, SecretString,
};

#[cfg(feature = "saslprep")]
use crate::saslprep::{prepare_query, prepare_stored};

/// A strict profile for protocols that intentionally limit credentials to printable ASCII.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AsciiProfile;

impl AsciiProfile {
    /// Prepares an authentication identity and password under the ASCII profile.
    pub fn prepare(
        authentication_identity: &str,
        password: SecretString,
    ) -> Result<PreparedCredentials, PreparationError> {
        if !is_ascii_identity(authentication_identity) {
            return Err(PreparationError::InvalidAuthenticationIdentity);
        }
        let identity =
            PreparedAuthenticationIdentity::from_protocol_profile(authentication_identity)?;
        let password = Self::prepare_password(password)?;
        Ok(PreparedCredentials::from_protocol_profile(
            identity, None, password,
        ))
    }

    /// Prepares only a password for server verifier generation.
    pub fn prepare_password(password: SecretString) -> Result<PreparedPassword, PreparationError> {
        if !password
            .expose_secret()
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(PreparationError::InvalidPassword);
        }
        Ok(PreparedPassword::from_protocol_profile(
            password.into_secret_bytes(),
        ))
    }

    /// Prepares one decoded authentication identity under the printable-ASCII profile.
    pub fn prepare_authentication_identity(
        identity: &ReceivedAuthenticationIdentity,
    ) -> Result<PreparedAuthenticationIdentity, PreparationError> {
        if !is_ascii_identity(identity.as_str()) {
            return Err(PreparationError::InvalidAuthenticationIdentity);
        }
        PreparedAuthenticationIdentity::from_protocol_profile(identity.as_str())
    }

    /// Prepares one decoded authorization identity under the printable-ASCII profile.
    pub fn prepare_authorization_identity(
        identity: &ReceivedAuthorizationIdentity,
    ) -> Result<PreparedAuthorizationIdentity, PreparationError> {
        if !is_ascii_identity(identity.as_str()) {
            return Err(PreparationError::InvalidAuthorizationIdentity);
        }
        PreparedAuthorizationIdentity::from_protocol_profile(identity.as_str())
    }

    /// Applies ASCII as a complete application profile to both server identities.
    ///
    /// Unlike SCRAM's authentication-identity rules, authorization-identity
    /// preparation is defined by the containing SASL application protocol.
    pub fn prepare_server_identities(
        authentication_identity: &ReceivedAuthenticationIdentity,
        authorization_identity: Option<&ReceivedAuthorizationIdentity>,
    ) -> Result<
        (
            PreparedAuthenticationIdentity,
            Option<PreparedAuthorizationIdentity>,
        ),
        PreparationError,
    > {
        let authentication_identity =
            Self::prepare_authentication_identity(authentication_identity)?;
        let authorization_identity = authorization_identity
            .map(Self::prepare_authorization_identity)
            .transpose()?;
        Ok((authentication_identity, authorization_identity))
    }
}

fn is_ascii_identity(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// The RFC 5802 `SASLprep` credential profile.
#[cfg(feature = "saslprep")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rfc5802Profile;

#[cfg(feature = "saslprep")]
impl Rfc5802Profile {
    /// Applies query-string `SASLprep` to the identity and stored-string `SASLprep` to the password.
    pub fn prepare(
        authentication_identity: &str,
        password: SecretString,
    ) -> Result<PreparedCredentials, PreparationError> {
        let identity = prepare_query(
            authentication_identity,
            PreparationError::InvalidAuthenticationIdentity,
        )?;
        if identity.is_empty() {
            return Err(PreparationError::InvalidAuthenticationIdentity);
        }
        let identity = PreparedAuthenticationIdentity::from_protocol_profile(identity)?;
        let password = Self::prepare_password(password)?;
        Ok(PreparedCredentials::from_protocol_profile(
            identity, None, password,
        ))
    }

    /// Applies stored-string `SASLprep` to a password for server verifier generation.
    pub fn prepare_password(password: SecretString) -> Result<PreparedPassword, PreparationError> {
        let prepared_password = prepare_stored(password.expose_secret())?;
        drop(password);
        Ok(PreparedPassword::from_protocol_profile(
            prepared_password.into_secret_bytes(),
        ))
    }

    /// Applies the RFC 5802 query profile to a decoded authentication identity.
    ///
    /// Authorization-identity preparation belongs to the containing SASL
    /// application protocol and is intentionally not provided by this profile.
    pub fn prepare_authentication_identity(
        identity: &ReceivedAuthenticationIdentity,
    ) -> Result<PreparedAuthenticationIdentity, PreparationError> {
        let identity = prepare_query(
            identity.as_str(),
            PreparationError::InvalidAuthenticationIdentity,
        )?;
        PreparedAuthenticationIdentity::from_protocol_profile(identity)
    }
}
