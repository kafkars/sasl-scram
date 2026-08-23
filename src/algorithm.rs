//! Complete SCRAM algorithm profiles exposed by the crate.

/// A supported, internally coherent SCRAM algorithm profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Algorithm {
    /// The standards-track SCRAM-SHA-256 profile.
    Sha256,

    /// A widely deployed SHA-512 extension that is not IANA-registered.
    ///
    /// The latest proposal is an expired Internet-Draft, so enabling this
    /// variant must not be represented as RFC conformance.
    #[cfg(feature = "sha512")]
    Sha512,
}

impl Algorithm {
    #[cfg(any(feature = "sha256", feature = "sha512"))]
    pub(crate) const fn output_len(self) -> Option<usize> {
        match self {
            Self::Sha256 => {
                if cfg!(feature = "sha256") {
                    Some(32)
                } else {
                    None
                }
            }
            #[cfg(feature = "sha512")]
            Self::Sha512 => Some(64),
        }
    }

    /// Returns the non-PLUS SASL mechanism name.
    pub const fn mechanism_name(self) -> &'static str {
        match self {
            Self::Sha256 => "SCRAM-SHA-256",
            #[cfg(feature = "sha512")]
            Self::Sha512 => "SCRAM-SHA-512",
        }
    }

    /// Returns the channel-binding SASL mechanism name.
    pub const fn plus_mechanism_name(self) -> &'static str {
        match self {
            Self::Sha256 => "SCRAM-SHA-256-PLUS",
            #[cfg(feature = "sha512")]
            Self::Sha512 => "SCRAM-SHA-512-PLUS",
        }
    }
}
