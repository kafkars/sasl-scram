//! Bounded, secret-safe error vocabulary.

#[path = "error_display.rs"]
mod error_display;

use crate::{AttributeName, NonceError, PolicyError};

/// A structural SCRAM protocol failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// A message exceeded the configured byte limit.
    MessageTooLarge {
        /// The observed message length.
        length: usize,
        /// The configured maximum.
        maximum: usize,
    },
    /// A message contained more attributes than permitted.
    TooManyAttributes {
        /// The configured maximum attribute count.
        maximum: usize,
    },
    /// Attribute syntax or separators were malformed.
    MalformedMessage,
    /// A required reserved attribute was absent.
    MissingAttribute(AttributeName),
    /// A reserved attribute appeared more than once.
    DuplicateAttribute(AttributeName),
    /// Required attributes were not in their protocol order.
    InvalidAttributeOrder,
    /// A Base64 value was invalid or noncanonical.
    InvalidBase64,
    /// A SASL identity used malformed SCRAM escaping.
    InvalidIdentityEscape,
    /// An iteration count was zero, malformed, noncanonical, or too large.
    InvalidIterationCount,
    /// A nonce was empty, malformed, or oversized.
    InvalidNonce,
    /// A channel-binding name was malformed.
    InvalidChannelBindingName,
    /// The peer required an extension this crate does not implement.
    UnsupportedMandatoryExtension,
    /// A reserved attribute appeared where only optional extensions are legal.
    UnexpectedAttribute(AttributeName),
    /// An extension region exceeded its configured byte limit.
    ExtensionsTooLarge {
        /// The observed encoded extension-region length.
        length: usize,
        /// The configured maximum.
        maximum: usize,
    },
    /// A decoded salt exceeded its configured byte limit.
    SaltTooLarge {
        /// The decoded salt length.
        length: usize,
        /// The configured maximum.
        maximum: usize,
    },
    /// Decoded channel-binding data exceeded its configured byte limit.
    ChannelBindingTooLarge {
        /// The decoded channel-binding length.
        length: usize,
        /// The configured maximum.
        maximum: usize,
    },
}

/// Credential preparation failed without retaining credential contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreparationError {
    /// The authentication identity was empty or prohibited by the profile.
    InvalidAuthenticationIdentity,
    /// The authorization identity was prohibited by the profile.
    InvalidAuthorizationIdentity,
    /// Preparation changed whether the client supplied an authorization identity.
    AuthorizationIdentityMismatch,
    /// The password was prohibited by the profile.
    InvalidPassword,
}

/// A bounded SCRAM peer-error classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PeerError {
    /// The peer rejected message encoding.
    InvalidEncoding,
    /// The peer does not support requested extensions.
    ExtensionsNotSupported,
    /// The peer rejected the proof.
    InvalidProof,
    /// Channel-binding bytes did not match.
    ChannelBindingsDoNotMatch,
    /// The server reported channel binding was available during downgrade detection.
    ServerSupportsChannelBinding,
    /// The server does not support channel binding.
    ChannelBindingNotSupported,
    /// The binding type is unsupported.
    UnsupportedChannelBindingType,
    /// The peer reported an unknown user.
    UnknownUser,
    /// The peer rejected username encoding.
    InvalidUsernameEncoding,
    /// The peer lacked resources.
    NoResources,
    /// A known generic server error was returned.
    OtherError,
    /// An unknown peer value was mapped without retaining its text.
    Other,
}

/// Authentication failed after structurally valid protocol processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthenticationError {
    /// The client proof did not verify.
    InvalidProof,
    /// The server verifier did not verify.
    InvalidServerSignature,
    /// The peer returned a bounded error classification.
    PeerRejected(PeerError),
    /// Application authorization was denied.
    AuthorizationDenied,
}

/// A cryptographic operation failed without exposing intermediates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The requested cryptographic implementation is unavailable.
    Unavailable,
}

/// A consuming state-machine transition was invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StateError {
    /// A message was supplied to the wrong or terminal state.
    UnexpectedMessage,
}

/// The top-level library error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Protocol structure failed.
    Protocol(ProtocolError),
    /// Application policy rejected the exchange.
    Policy(PolicyError),
    /// Authentication failed.
    Authentication(AuthenticationError),
    /// Credential preparation failed.
    Preparation(PreparationError),
    /// Cryptographic processing failed.
    Crypto(CryptoError),
    /// State-machine order was violated.
    State(StateError),
    /// Caller-supplied nonce generation failed.
    Nonce(NonceError),
}

impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<PolicyError> for Error {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<AuthenticationError> for Error {
    fn from(error: AuthenticationError) -> Self {
        Self::Authentication(error)
    }
}

impl From<PreparationError> for Error {
    fn from(error: PreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<StateError> for Error {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<NonceError> for Error {
    fn from(error: NonceError) -> Self {
        Self::Nonce(error)
    }
}
