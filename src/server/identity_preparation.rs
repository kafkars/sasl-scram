//! Received client-first identities awaiting caller-selected preparation.

use core::fmt;

use zeroize::ZeroizeOnDrop;

use crate::{
    ChannelBindingMode, Error, PolicyError, PreparationError, PreparedAuthenticationIdentity,
    PreparedAuthorizationIdentity, ReceivedAuthenticationIdentity, ReceivedAuthorizationIdentity,
    SecretBytes, Server, ServerPolicy,
    message::{ClientFirst, Gs2Flag},
};

use super::NeedCredential;

/// Parsed client-first state awaiting one explicit server identity profile.
pub struct NeedIdentityPreparation {
    algorithm: crate::Algorithm,
    channel_binding: ChannelBindingMode,
    policy: ServerPolicy,
    authentication_identity: ReceivedAuthenticationIdentity,
    authorization_identity: Option<ReceivedAuthorizationIdentity>,
    gs2_header: SecretBytes,
    client_first_bare: SecretBytes,
    client_nonce: SecretBytes,
}

impl ZeroizeOnDrop for NeedIdentityPreparation {}

impl NeedIdentityPreparation {
    /// Returns the decoded, unescaped authentication identity before preparation.
    pub const fn authentication_identity(&self) -> &ReceivedAuthenticationIdentity {
        &self.authentication_identity
    }

    /// Returns the decoded, unescaped authorization identity before preparation.
    pub const fn authorization_identity(&self) -> Option<&ReceivedAuthorizationIdentity> {
        self.authorization_identity.as_ref()
    }

    /// Accepts identities produced by documented profiles and requests lookup.
    ///
    /// The optional prepared authorization identity must preserve whether the
    /// received client-first message contained `a=`.
    pub fn accept_prepared(
        self,
        authentication_identity: PreparedAuthenticationIdentity,
        authorization_identity: Option<PreparedAuthorizationIdentity>,
    ) -> Result<NeedCredential, Error> {
        if self.authorization_identity.is_some() != authorization_identity.is_some() {
            return Err(PreparationError::AuthorizationIdentityMismatch.into());
        }
        let Self {
            algorithm,
            channel_binding,
            policy,
            authentication_identity: _,
            authorization_identity: _,
            gs2_header,
            client_first_bare,
            client_nonce,
        } = self;
        if authentication_identity.as_str().len() > policy.resources().max_identity_bytes() {
            return Err(PreparationError::InvalidAuthenticationIdentity.into());
        }
        if authorization_identity.as_ref().is_some_and(|identity| {
            identity.as_str().len() > policy.resources().max_authorization_identity_bytes()
        }) {
            return Err(PreparationError::InvalidAuthorizationIdentity.into());
        }
        Ok(NeedCredential {
            algorithm,
            channel_binding,
            policy,
            authentication_identity,
            authorization_identity,
            gs2_header,
            client_first_bare,
            client_nonce,
        })
    }
}

impl fmt::Debug for NeedIdentityPreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeedIdentityPreparation")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl Server {
    /// Consumes a bounded client-first message and requests identity preparation.
    ///
    /// ```compile_fail
    /// fn receive_twice(server: sasl_scram::Server, message: &[u8]) {
    ///     let _first = server.receive_client_first(message);
    ///     let _second = server.receive_client_first(message);
    /// }
    /// ```
    pub fn receive_client_first(self, input: &[u8]) -> Result<NeedIdentityPreparation, Error> {
        let Server {
            config,
            channel_binding,
        } = self;
        let policy = config.policy;
        let parsed = ClientFirst::parse(input, &policy.resources())?;
        validate_channel_binding_flag(&channel_binding, parsed.channel_binding_flag())?;
        Ok(NeedIdentityPreparation {
            algorithm: config.algorithm,
            channel_binding,
            policy,
            authentication_identity: ReceivedAuthenticationIdentity::from_wire(
                parsed.decode_authentication_identity()?,
            ),
            authorization_identity: parsed
                .decode_authorization_identity()?
                .map(ReceivedAuthorizationIdentity::from_wire),
            gs2_header: SecretBytes::new(parsed.gs2_header()),
            client_first_bare: SecretBytes::new(parsed.bare()),
            client_nonce: SecretBytes::new(parsed.nonce()),
        })
    }
}

fn validate_channel_binding_flag(
    mode: &ChannelBindingMode,
    flag: Gs2Flag<'_>,
) -> Result<(), PolicyError> {
    match (mode, flag) {
        (
            ChannelBindingMode::Unsupported,
            Gs2Flag::Unsupported | Gs2Flag::AvailableButNotNegotiated,
        )
        | (ChannelBindingMode::AvailableButNotNegotiated, Gs2Flag::Unsupported) => Ok(()),
        (
            ChannelBindingMode::AvailableButNotNegotiated | ChannelBindingMode::Required(_),
            Gs2Flag::AvailableButNotNegotiated,
        )
        | (ChannelBindingMode::Required(_), Gs2Flag::Unsupported) => {
            Err(PolicyError::ChannelBindingRequired)
        }
        (
            ChannelBindingMode::Unsupported | ChannelBindingMode::AvailableButNotNegotiated,
            Gs2Flag::Required(_),
        ) => Err(PolicyError::ChannelBindingNotPermitted),
        (ChannelBindingMode::Required(expected), Gs2Flag::Required(received)) => {
            if expected.name().as_str().as_bytes() == received {
                Ok(())
            } else {
                Err(PolicyError::UnsupportedChannelBindingType)
            }
        }
    }
}
