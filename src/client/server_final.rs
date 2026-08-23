//! Server-final verification and terminal client authentication.

use core::fmt;
use zeroize::ZeroizeOnDrop;

use crate::{
    AuthenticationError, AuthenticationProperties, ClientPolicy, Error, PolicyError, SecretBytes,
    message::{ServerFinal, ServerFinalOutcome, decode_base64},
};

/// A client state that accepts exactly one server-final message.
pub struct AwaitingServerFinal {
    pub(super) properties: AuthenticationProperties,
    pub(super) expected_server_signature: SecretBytes,
    pub(super) policy: ClientPolicy,
}

impl ZeroizeOnDrop for AwaitingServerFinal {}

impl AwaitingServerFinal {
    /// Verifies the server signature before returning authenticated success.
    ///
    /// ```compile_fail
    /// fn finish_twice(state: sasl_scram::AwaitingServerFinal, message: &[u8]) {
    ///     let _first = state.receive_server_final(message);
    ///     let _second = state.receive_server_final(message);
    /// }
    /// ```
    pub fn receive_server_final(self, input: &[u8]) -> Result<ClientAuthenticated, Error> {
        let server_final = ServerFinal::parse(input, &self.policy.resources())?;
        let verifier = match server_final.outcome() {
            ServerFinalOutcome::Rejected(error) => {
                return Err(AuthenticationError::PeerRejected(error).into());
            }
            ServerFinalOutcome::Verified(verifier) => verifier.expose_base64(),
        };
        let received = SecretBytes::new(decode_base64(verifier)?.into_boxed_slice());
        let output_len = self
            .properties
            .algorithm()
            .output_len()
            .ok_or(PolicyError::AlgorithmNotPermitted)?;
        if received.len() != output_len
            || !crate::crypto::verify_server_signature(
                self.expected_server_signature.expose_secret(),
                received.expose_secret(),
            )
        {
            return Err(AuthenticationError::InvalidServerSignature.into());
        }
        Ok(ClientAuthenticated {
            properties: self.properties,
        })
    }
}

impl fmt::Debug for AwaitingServerFinal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwaitingServerFinal")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Terminal proof that the selected SCRAM server signature was verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientAuthenticated {
    properties: AuthenticationProperties,
}

impl ClientAuthenticated {
    /// Returns the algorithm whose complete transcript was authenticated.
    pub const fn algorithm(&self) -> crate::Algorithm {
        self.properties.algorithm()
    }

    /// Returns the nonsecret mechanism properties proven by the exchange.
    pub const fn properties(&self) -> &AuthenticationProperties {
        &self.properties
    }
}
