//! Public client state, policy, feature-selection, and redaction boundaries.

#![cfg(feature = "sha256")]

use core::num::{NonZeroU32, NonZeroUsize};

use sasl_scram::{
    Algorithm, AsciiProfile, AuthenticationError, ChannelBindingMode, Client, ClientConfig,
    ClientPolicy, Error, IterationPolicy, NonceError, NonceSource, PolicyError,
    PreparedAuthenticationIdentity, PreparedAuthorizationIdentity, PreparedCredentials,
    ProtocolError, ResourceLimits, SaltPolicy, SecretString,
};

const NONCE: &str = "AAAAAAAAAAAAAAAAAAAA";

struct ZeroNonce;

impl NonceSource for ZeroNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        output.fill(0);
        Ok(())
    }
}

struct FailingNonce;

impl NonceSource for FailingNonce {
    fn fill(&mut self, _output: &mut [u8]) -> Result<(), NonceError> {
        Err(NonceError::unavailable())
    }
}

struct TrackingNonce(usize);

impl NonceSource for TrackingNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        self.0 += 1;
        output.fill(0);
        Ok(())
    }
}

#[test]
fn server_nonce_must_begin_with_and_strictly_extend_client_nonce() -> Result<(), Error> {
    for nonce in [NONCE, "differentSERVER", "AAAAAAAAAAAAAAAAAAABSERVER"] {
        let (client, _) = start(ClientPolicy::default())?;
        let message = format!("r={nonce},s=c2FsdA==,i=4096");
        assert!(matches!(
            client.receive_server_first(message.as_bytes()),
            Err(Error::Protocol(ProtocolError::InvalidNonce))
        ));
    }
    Ok(())
}

#[test]
fn iteration_policy_rejects_work_before_derivation_state() -> Result<(), Error> {
    for (iterations, expected) in [
        (4095, PolicyError::IterationCountTooLow),
        (1_000_001, PolicyError::IterationCountTooHigh),
    ] {
        let (client, _) = start(ClientPolicy::default())?;
        let message = format!("r={NONCE}SERVER,s=c2FsdA==,i={iterations}");
        assert!(matches!(
            client.receive_server_first(message.as_bytes()),
            Err(Error::Policy(error)) if error == expected
        ));
    }
    Ok(())
}

#[test]
fn salt_policy_rejects_empty_and_profile_short_salts_before_derivation() -> Result<(), Error> {
    let (client, _) = start(ClientPolicy::default())?;
    assert!(matches!(
        client.receive_server_first(format!("r={NONCE}SERVER,s=,i=4096").as_bytes()),
        Err(Error::Policy(PolicyError::SaltTooShort {
            length: 0,
            minimum: 1
        }))
    ));

    let minimum = NonZeroUsize::MIN.saturating_add(15);
    let salt = SaltPolicy::new(minimum, NonZeroUsize::MIN.saturating_add(1023))?;
    let policy = ClientPolicy::default().with_salt_policy(salt);
    let (client, _) = start(policy)?;
    assert!(matches!(
        client.receive_server_first(format!("r={NONCE}SERVER,s=c2FsdA==,i=4096").as_bytes()),
        Err(Error::Policy(PolicyError::SaltTooShort {
            length: 4,
            minimum: 16
        }))
    ));
    Ok(())
}

#[test]
fn final_message_limit_is_checked_before_expensive_derivation() -> Result<(), Error> {
    let resources = ResourceLimits::builder()
        .max_message_bytes(120)
        .max_channel_binding_bytes(1)
        .build()?;
    let one = NonZeroU32::MIN;
    let policy = ClientPolicy::new(resources, IterationPolicy::new(one, one)?);
    assert!(matches!(
        start(policy),
        Err(Error::Policy(PolicyError::InvalidResourceLimit))
    ));
    Ok(())
}

#[test]
fn invalid_server_signature_and_bounded_peer_error_never_authenticate() -> Result<(), Error> {
    let policy = low_cost_policy()?;
    let (client, _) = start(policy)?;
    let pending =
        client.receive_server_first(format!("r={NONCE}SERVER,s=c2FsdA==,i=1").as_bytes())?;
    let (client, _) = pending.derive()?;
    assert!(matches!(
        client.receive_server_final(b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        Err(Error::Authentication(
            AuthenticationError::InvalidServerSignature
        ))
    ));

    let (client, _) = start(policy)?;
    let pending =
        client.receive_server_first(format!("r={NONCE}SERVER,s=c2FsdA==,i=1").as_bytes())?;
    let (client, _) = pending.derive()?;
    assert!(matches!(
        client.receive_server_final(b"e=unknown-peer-text"),
        Err(Error::Authentication(AuthenticationError::PeerRejected(_)))
    ));
    Ok(())
}

#[test]
fn client_states_are_send_and_debug_output_is_redacted() -> Result<(), Error> {
    assert_send::<sasl_scram::AwaitingServerFirst>();
    assert_send::<sasl_scram::PendingDerivation>();
    assert_send::<sasl_scram::AwaitingServerFinal>();
    let (client, first) = start(low_cost_policy()?)?;
    let pending =
        client.receive_server_first(format!("r={NONCE}SERVER,s=c2FsdA==,i=1").as_bytes())?;
    assert!(!format!("{pending:?}").contains("pencil"));
    assert!(!format!("{pending:?}").contains(NONCE));
    let (client, final_message) = pending.derive()?;
    assert!(!format!("{client:?}").contains(NONCE));
    assert!(!format!("{first:?}").contains(NONCE));
    assert!(!format!("{final_message:?}").contains(NONCE));
    Ok(())
}

#[test]
fn configured_client_surfaces_nonce_failure() -> Result<(), Error> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::Unsupported)
        .build()?;
    assert!(matches!(
        Client::start(config, &mut FailingNonce),
        Err(Error::Nonce(_))
    ));
    Ok(())
}

#[test]
fn static_client_configuration_failures_precede_randomness() -> Result<(), Error> {
    let identity_limits = ResourceLimits::builder().max_identity_bytes(4).build()?;
    let credentials = AsciiProfile::prepare("oversized", SecretString::new("pencil"))?;
    assert_static_failure(
        ClientConfig::builder(Algorithm::Sha256)
            .credentials(credentials)
            .channel_binding(ChannelBindingMode::Unsupported)
            .policy(ClientPolicy::new(
                identity_limits,
                IterationPolicy::default(),
            ))
            .build(),
        PolicyError::AuthenticationIdentityTooLong {
            length: 9,
            maximum: 4,
        },
    );

    let authorization_limits = ResourceLimits::builder()
        .max_authorization_identity_bytes(4)
        .build()?;
    let credentials = PreparedCredentials::from_protocol_profile(
        PreparedAuthenticationIdentity::from_protocol_profile("user")?,
        Some(PreparedAuthorizationIdentity::from_protocol_profile(
            "oversized",
        )?),
        AsciiProfile::prepare_password(SecretString::new("pencil"))?,
    );
    assert_static_failure(
        ClientConfig::builder(Algorithm::Sha256)
            .credentials(credentials)
            .channel_binding(ChannelBindingMode::Unsupported)
            .policy(ClientPolicy::new(
                authorization_limits,
                IterationPolicy::default(),
            ))
            .build(),
        PolicyError::AuthorizationIdentityTooLong {
            length: 9,
            maximum: 4,
        },
    );

    let capacity_limits = ResourceLimits::builder()
        .max_message_bytes(120)
        .max_identity_bytes(110)
        .max_authorization_identity_bytes(1)
        .max_nonce_bytes(20)
        .max_channel_binding_bytes(1)
        .build()?;
    let credentials = AsciiProfile::prepare(&"u".repeat(100), SecretString::new("pencil"))?;
    assert_static_failure(
        ClientConfig::builder(Algorithm::Sha256)
            .credentials(credentials)
            .channel_binding(ChannelBindingMode::Unsupported)
            .policy(ClientPolicy::new(
                capacity_limits,
                IterationPolicy::default(),
            ))
            .build(),
        PolicyError::InvalidResourceLimit,
    );
    Ok(())
}

fn assert_static_failure(config: Result<ClientConfig, PolicyError>, expected: PolicyError) {
    let mut nonce = TrackingNonce(0);
    let result = config
        .map_err(Error::from)
        .and_then(|config| Client::start(config, &mut nonce).map(|_| ()));
    assert!(matches!(result, Err(Error::Policy(error)) if error == expected));
    assert_eq!(nonce.0, 0);
}

#[test]
fn supported_but_not_negotiated_emits_the_gs2_y_flag() -> Result<(), Error> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::AvailableButNotNegotiated)
        .build()?;
    let (_, message) = Client::start(config, &mut ZeroNonce)?;
    assert!(message.as_bytes().starts_with(b"y,,n=user,r="));
    Ok(())
}

#[cfg(feature = "sha512")]
#[test]
fn sha512_feature_enables_the_complete_client_profile() -> Result<(), Error> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let config = ClientConfig::builder(Algorithm::Sha512)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::Unsupported)
        .build()?;
    let (_, first) = Client::start(config, &mut ZeroNonce)?;
    assert!(first.as_bytes().starts_with(b"n,,n=user,r="));
    Ok(())
}

fn start(
    policy: ClientPolicy,
) -> Result<(sasl_scram::AwaitingServerFirst, sasl_scram::OutboundMessage), Error> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::Unsupported)
        .policy(policy)
        .build()?;
    Client::start(config, &mut ZeroNonce)
}

fn low_cost_policy() -> Result<ClientPolicy, Error> {
    let one = NonZeroU32::MIN;
    Ok(ClientPolicy::new(
        ResourceLimits::default(),
        IterationPolicy::new(one, one)?,
    ))
}

fn assert_send<T: Send>() {}
