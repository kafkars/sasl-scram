//! Client-first construction and the first consuming state.

use core::fmt;

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    ChannelBindingMode, ClientConfig, ClientPolicy, Error, NonceSource, OutboundMessage,
    PreparedCredentials, SecretBytes,
    message::{ClientFirst, encode_client_first},
};

use super::CLIENT_NONCE_ENTROPY_BYTES;

/// Namespace for starting a SCRAM client conversation.
#[derive(Debug)]
pub enum Client {}

impl Client {
    /// Consumes one configuration and emits a client-first message with 120 bits of nonce entropy.
    pub fn start(
        config: ClientConfig,
        nonce_source: &mut impl NonceSource,
    ) -> Result<(AwaitingServerFirst, OutboundMessage), Error> {
        let mut entropy = Zeroizing::new([0_u8; CLIENT_NONCE_ENTROPY_BYTES]);
        nonce_source.fill(entropy.as_mut())?;
        let nonce = crate::message::encode_base64(entropy.as_ref());
        let limits = config.policy.resources();
        let first = encode_client_first(
            &config.channel_binding,
            config.credentials.authentication_identity(),
            config.credentials.authorization_identity(),
            &nonce,
            &limits,
        )?;
        let client_first_bare = {
            let parsed = ClientFirst::parse(first.as_bytes(), &limits)?;
            SecretBytes::new(parsed.bare())
        };
        let state = AwaitingServerFirst {
            algorithm: config.algorithm,
            credentials: config.credentials,
            channel_binding: config.channel_binding,
            policy: config.policy,
            client_nonce: SecretBytes::new(nonce.into_boxed_slice()),
            client_first_bare,
        };
        Ok((state, first))
    }
}

/// A client state that accepts exactly one server-first message.
///
/// ```compile_fail
/// fn out_of_order(state: sasl_scram::AwaitingServerFirst) {
///     let _authenticated = state.receive_server_final(b"v=");
/// }
/// ```
pub struct AwaitingServerFirst {
    pub(super) algorithm: crate::Algorithm,
    pub(super) credentials: PreparedCredentials,
    pub(super) channel_binding: ChannelBindingMode,
    pub(super) policy: ClientPolicy,
    pub(super) client_nonce: SecretBytes,
    pub(super) client_first_bare: SecretBytes,
}

impl ZeroizeOnDrop for AwaitingServerFirst {}

impl fmt::Debug for AwaitingServerFirst {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwaitingServerFirst")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
