//! Bounded errors for application-selected security policy.

/// An application-selected security policy rejected otherwise valid input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PolicyError {
    /// Client configuration omitted prepared credentials.
    MissingCredentials,
    /// A prepared authentication identity exceeded the configured limit.
    AuthenticationIdentityTooLong {
        /// The supplied prepared identity length.
        length: usize,
        /// The configured maximum.
        maximum: usize,
    },
    /// A prepared authorization identity exceeded the configured limit.
    AuthorizationIdentityTooLong {
        /// The supplied prepared identity length.
        length: usize,
        /// The configured maximum.
        maximum: usize,
    },
    /// The supplied iteration count was below policy.
    IterationCountTooLow,
    /// The supplied iteration count was above policy.
    IterationCountTooHigh,
    /// A required channel binding was unavailable.
    ChannelBindingRequired,
    /// Channel-binding data was supplied to an unbound exchange.
    ChannelBindingNotPermitted,
    /// The selected algorithm was not permitted.
    AlgorithmNotPermitted,
    /// A resource limit was zero or internally inconsistent.
    InvalidResourceLimit,
    /// A channel-binding payload exceeded the resource policy.
    ChannelBindingTooLarge {
        /// The supplied binding-data length.
        length: usize,
        /// The configured maximum.
        maximum: usize,
    },
    /// A channel-binding name was empty or syntactically invalid.
    InvalidChannelBindingName,
    /// A verifier record was malformed or inconsistent with its algorithm.
    InvalidCredential,
    /// A salt was shorter than credential policy permits.
    SaltTooShort {
        /// The supplied decoded salt length.
        length: usize,
        /// The configured minimum.
        minimum: usize,
    },
    /// A salt was longer than credential policy permits.
    SaltTooLong {
        /// The supplied decoded salt length.
        length: usize,
        /// The configured maximum.
        maximum: usize,
    },
    /// A concealment key was shorter than the required security boundary.
    ConcealmentKeyTooShort {
        /// The supplied key length.
        length: usize,
        /// The required minimum.
        minimum: usize,
    },
    /// The peer selected a channel-binding type other than the configured type.
    UnsupportedChannelBindingType,
    /// Client configuration omitted an explicit channel-binding mode.
    MissingChannelBindingMode,
}
