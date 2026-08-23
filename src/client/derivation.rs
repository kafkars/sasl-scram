//! Explicit PBKDF2 boundary and client-proof construction.

use core::fmt;
use zeroize::ZeroizeOnDrop;

use crate::{
    Algorithm, AuthenticationProperties, ClientPolicy, Error, IterationCount, OutboundMessage,
    PreparedPassword, SecretBytes, client::AwaitingServerFinal, message::ClientFinalWithoutProof,
};

/// One transcript-bound challenge awaiting explicit PBKDF2 derivation.
///
/// This value is `Send`, is not cloneable, redacts `Debug`, and owns all
/// password and transcript material with zeroizing fields.
///
/// ```compile_fail
/// fn clone_pending(state: &sasl_scram::PendingDerivation) {
///     let _copy = Clone::clone(state);
/// }
/// ```
pub struct PendingDerivation {
    pub(super) algorithm: Algorithm,
    pub(super) password: PreparedPassword,
    pub(super) salt: SecretBytes,
    pub(super) iterations: IterationCount,
    pub(super) auth_message: OutboundMessage,
    pub(super) client_final: ClientFinalWithoutProof,
    pub(super) properties: AuthenticationProperties,
    pub(super) policy: ClientPolicy,
}

impl ZeroizeOnDrop for PendingDerivation {}

impl PendingDerivation {
    /// Performs PBKDF2 and emits the client-final proof message.
    ///
    /// ```compile_fail
    /// fn derive_twice(state: sasl_scram::PendingDerivation) {
    ///     let _first = state.derive();
    ///     let _second = state.derive();
    /// }
    /// ```
    pub fn derive(self) -> Result<(AwaitingServerFinal, OutboundMessage), Error> {
        let Self {
            algorithm,
            password,
            salt,
            iterations,
            auth_message,
            client_final,
            properties,
            policy,
        } = self;
        let derived = crate::crypto::derive_client(
            algorithm,
            password.expose_secret(),
            salt.expose_secret(),
            iterations.get(),
            auth_message.as_bytes(),
        )?;
        drop(password);
        drop(salt);
        drop(auth_message);
        let message = client_final.finish(derived.proof(), &policy.resources())?;
        let state = AwaitingServerFinal {
            properties,
            expected_server_signature: derived.into_server_signature(),
            policy,
        };
        Ok((state, message))
    }
}

impl fmt::Debug for PendingDerivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingDerivation")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
