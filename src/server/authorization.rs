//! Caller-owned authorization continuation and terminal server outcome.

use core::convert::Infallible;
use core::fmt;

use crate::{
    AuthenticationProperties, Error, OutboundMessage, PeerError, PreparedAuthenticationIdentity,
    PreparedAuthorizationIdentity, SecretBytes, ServerPolicy,
    message::{encode_server_final_error, encode_server_final_verifier},
};

/// Borrowed, proof-verified request presented to application authorization policy.
#[derive(Clone, Copy)]
pub struct AuthorizationRequest<'a, P> {
    authentication_identity: &'a PreparedAuthenticationIdentity,
    authorization_identity: Option<&'a PreparedAuthorizationIdentity>,
    authenticated_principal: &'a P,
}

impl<'a, P> AuthorizationRequest<'a, P> {
    /// Returns the identity whose SCRAM proof was verified.
    pub const fn authentication_identity(&self) -> &'a PreparedAuthenticationIdentity {
        self.authentication_identity
    }

    /// Returns the optional identity the client requested to act as.
    pub const fn authorization_identity(&self) -> Option<&'a PreparedAuthorizationIdentity> {
        self.authorization_identity
    }

    /// Returns the caller-owned principal associated with the verified credential.
    pub const fn authenticated_principal(&self) -> &'a P {
        self.authenticated_principal
    }
}

impl<P> fmt::Debug for AuthorizationRequest<'_, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequest")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Proof-verified state awaiting one application authorization decision.
///
/// ```compile_fail
/// fn finish_twice(state: sasl_scram::PendingAuthorization<()>) {
///     let _first = state.authorize(());
///     let _second = state.deny();
/// }
/// ```
pub struct PendingAuthorization<P> {
    pub(super) properties: AuthenticationProperties,
    pub(super) policy: ServerPolicy,
    pub(super) authentication_identity: PreparedAuthenticationIdentity,
    pub(super) authorization_identity: Option<PreparedAuthorizationIdentity>,
    pub(super) principal: P,
    pub(super) server_signature: SecretBytes,
}

impl<P> PendingAuthorization<P> {
    /// Borrows the proof-verified request for caller-owned authorization work.
    pub const fn request(&self) -> AuthorizationRequest<'_, P> {
        AuthorizationRequest {
            authentication_identity: &self.authentication_identity,
            authorization_identity: self.authorization_identity.as_ref(),
            authenticated_principal: &self.principal,
        }
    }

    /// Authorizes one effective principal and emits the server verifier.
    pub fn authorize<Z>(self, principal: Z) -> Result<AuthorizationOutcome<P, Z>, Error> {
        let Self {
            properties,
            policy,
            authentication_identity: _,
            authorization_identity: _,
            principal: authenticated_principal,
            server_signature,
        } = self;
        Ok(AuthorizationOutcome::Authorized {
            authenticated: ServerAuthenticated {
                properties,
                authenticated_principal,
                authorized_principal: principal,
            },
            server_final: encode_server_final_verifier(
                server_signature.expose_secret(),
                &policy.resources(),
            )?,
        })
    }

    /// Denies authorization and emits one bounded terminal peer error.
    pub fn deny(self) -> Result<AuthorizationOutcome<P, Infallible>, Error> {
        let Self {
            properties: _,
            policy,
            authentication_identity: _,
            authorization_identity: _,
            principal: _,
            server_signature: _,
        } = self;
        Ok(AuthorizationOutcome::Denied {
            server_final: encode_server_final_error(PeerError::OtherError, &policy.resources())?,
        })
    }
}

impl<P> fmt::Debug for PendingAuthorization<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAuthorization")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Result of one explicit application authorization decision.
#[non_exhaustive]
pub enum AuthorizationOutcome<A, Z> {
    /// Authorization succeeded and the server verifier is ready to send.
    Authorized {
        /// Terminal authenticated application principal.
        authenticated: ServerAuthenticated<A, Z>,
        /// Successful server-final verifier message.
        server_final: OutboundMessage,
    },
    /// Authorization failed and a bounded server error is ready to send.
    Denied {
        /// Server-final error message.
        server_final: OutboundMessage,
    },
}

impl<A, Z> fmt::Debug for AuthorizationOutcome<A, Z> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationOutcome")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Terminal proof of authentication and application authorization.
pub struct ServerAuthenticated<A, Z> {
    properties: AuthenticationProperties,
    authenticated_principal: A,
    authorized_principal: Z,
}

impl<A, Z> ServerAuthenticated<A, Z> {
    /// Returns the algorithm whose complete transcript was authenticated.
    pub const fn algorithm(&self) -> crate::Algorithm {
        self.properties.algorithm()
    }

    /// Returns the nonsecret mechanism properties proven by the exchange.
    pub const fn properties(&self) -> &AuthenticationProperties {
        &self.properties
    }

    /// Returns the principal associated with the verified SCRAM credential.
    pub const fn authenticated_principal(&self) -> &A {
        &self.authenticated_principal
    }

    /// Returns the effective principal granted by authorization policy.
    pub const fn authorized_principal(&self) -> &Z {
        &self.authorized_principal
    }

    /// Transfers both authenticated and authorized principals to the caller.
    pub fn into_principals(self) -> (A, Z) {
        (self.authenticated_principal, self.authorized_principal)
    }
}

impl<A, Z> fmt::Debug for ServerAuthenticated<A, Z> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerAuthenticated")
            .field("properties", &self.properties)
            .field("authenticated_principal", &"[REDACTED]")
            .field("authorized_principal", &"[REDACTED]")
            .finish()
    }
}
