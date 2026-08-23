//! Reserved SCRAM attribute names used in bounded diagnostics.

/// A reserved SCRAM attribute name safe to include in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AttributeName {
    /// GS2 authorization identity (`a`).
    AuthorizationIdentity,
    /// Channel-binding input (`c`).
    ChannelBinding,
    /// Server error (`e`).
    ServerError,
    /// Iteration count (`i`).
    IterationCount,
    /// Mandatory extension (`m`).
    MandatoryExtension,
    /// Authentication identity (`n`).
    AuthenticationIdentity,
    /// Client proof (`p`).
    Proof,
    /// Nonce (`r`).
    Nonce,
    /// Salt (`s`).
    Salt,
    /// Server verifier (`v`).
    Verifier,
}

impl AttributeName {
    pub(crate) const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'a' => Some(Self::AuthorizationIdentity),
            b'c' => Some(Self::ChannelBinding),
            b'e' => Some(Self::ServerError),
            b'i' => Some(Self::IterationCount),
            b'm' => Some(Self::MandatoryExtension),
            b'n' => Some(Self::AuthenticationIdentity),
            b'p' => Some(Self::Proof),
            b'r' => Some(Self::Nonce),
            b's' => Some(Self::Salt),
            b'v' => Some(Self::Verifier),
            _ => None,
        }
    }

    pub(crate) const fn as_byte(self) -> u8 {
        match self {
            Self::AuthorizationIdentity => b'a',
            Self::ChannelBinding => b'c',
            Self::ServerError => b'e',
            Self::IterationCount => b'i',
            Self::MandatoryExtension => b'm',
            Self::AuthenticationIdentity => b'n',
            Self::Proof => b'p',
            Self::Nonce => b'r',
            Self::Salt => b's',
            Self::Verifier => b'v',
        }
    }
}
