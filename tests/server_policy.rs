//! Server resource, algorithm-feature, credential, and nonce policy boundaries.

#![cfg(feature = "sha256")]

use core::num::{NonZeroU32, NonZeroUsize};

use sasl_scram::{
    Algorithm, AsciiProfile, ChannelBinding, ChannelBindingData, ChannelBindingMode,
    ChannelBindingName, Client, ClientConfig, ClientPolicy, ConcealmentKey, ConcealmentProfile,
    CredentialResponse, CryptoError, Error, IterationCount, IterationPolicy, NeedCredential,
    NeedIdentityPreparation, NonceError, NonceSource, PolicyError, ProtocolError, ResourceLimits,
    Salt, SaltPolicy, SecretBytes, SecretString, Server, ServerConfig, ServerCredential,
    ServerPolicy,
};

struct TrackingNonce {
    called: bool,
    fail: bool,
}

impl NonceSource for TrackingNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        self.called = true;
        if self.fail {
            return Err(NonceError::unavailable());
        }
        output.fill(1);
        Ok(())
    }
}

#[test]
fn combined_nonce_and_salt_limits_fail_before_randomness() -> Result<(), Error> {
    let resources = ResourceLimits::builder().max_nonce_bytes(39).build()?;
    let iterations = IterationPolicy::new(NonZeroU32::MIN, NonZeroU32::MIN)?;
    let policy = ServerPolicy::new(resources, iterations);

    let need = need_credential(policy)?;
    let mut nonce = TrackingNonce {
        called: false,
        fail: false,
    };
    let result = need.resume(
        CredentialResponse::Known {
            principal: (),
            credential: credential(b"0123456789abcdef", 1)?,
        },
        &mut nonce,
    );
    assert!(matches!(
        result,
        Err(Error::Protocol(ProtocolError::InvalidNonce))
    ));
    assert!(!nonce.called);

    let resources = ResourceLimits::builder().max_salt_bytes(15).build()?;
    let policy = ServerPolicy::new(resources, iterations);
    let need = need_credential(policy)?;
    let result = need.resume(
        CredentialResponse::Known {
            principal: (),
            credential: credential(b"0123456789abcdef", 1)?,
        },
        &mut nonce,
    );
    assert!(matches!(
        result,
        Err(Error::Protocol(ProtocolError::SaltTooLarge {
            maximum: 15,
            ..
        }))
    ));
    assert!(!nonce.called);
    Ok(())
}

#[test]
fn nonce_failure_is_opaque_and_consumes_the_continuation() -> Result<(), Error> {
    let policy = low_cost_policy()?;
    let need = need_credential(policy)?;
    let mut nonce = TrackingNonce {
        called: false,
        fail: true,
    };
    assert!(matches!(
        need.resume(
            CredentialResponse::Known {
                principal: (),
                credential: credential(b"0123456789abcdef", 1)?,
            },
            &mut nonce,
        ),
        Err(Error::Nonce(_))
    ));
    assert!(nonce.called);
    Ok(())
}

#[test]
fn server_salt_and_concealment_profiles_fail_before_randomness() -> Result<(), Error> {
    let one = NonZeroU32::MIN;
    let salt_policy = SaltPolicy::new(
        NonZeroUsize::MIN.saturating_add(16),
        NonZeroUsize::MIN.saturating_add(31),
    )?;
    let policy = ServerPolicy::new(ResourceLimits::default(), IterationPolicy::new(one, one)?)
        .with_salt_policy(salt_policy);
    let need = need_credential(policy)?;
    let mut nonce = TrackingNonce {
        called: false,
        fail: false,
    };
    assert!(matches!(
        need.resume(
            CredentialResponse::Known {
                principal: (),
                credential: credential(b"0123456789abcdef", 1)?,
            },
            &mut nonce,
        ),
        Err(Error::Policy(PolicyError::SaltTooShort {
            length: 16,
            minimum: 17
        }))
    ));
    assert!(!nonce.called);

    let resources = ResourceLimits::builder().max_salt_bytes(16).build()?;
    let policy = ServerPolicy::new(resources, IterationPolicy::new(one, one)?);
    let need = need_credential(policy)?;
    let key = ConcealmentKey::new(SecretBytes::new([0x44_u8; 32].as_slice()))?;
    assert!(matches!(
        need.conceal::<()>(
            &key,
            ConcealmentProfile::new(
                NonZeroUsize::MIN.saturating_add(16),
                IterationCount::new(one),
            ),
        ),
        Err(Error::Protocol(ProtocolError::SaltTooLarge {
            length: 17,
            maximum: 16
        }))
    ));
    Ok(())
}

#[test]
fn decoded_channel_binding_payload_is_bounded_before_proof_work() -> Result<(), Error> {
    let resources = ResourceLimits::builder()
        .max_channel_binding_bytes(1)
        .build()?;
    let one = NonZeroU32::MIN;
    let policy = ServerPolicy::new(resources, IterationPolicy::new(one, one)?);
    let need = prepare(
        Server::new(
            ServerConfig::builder(Algorithm::Sha256)
                .policy(policy)
                .build()?,
        )
        .receive_client_first(b"n,,n=user,r=client")?,
    )?;
    let (server, first) = need.resume(
        CredentialResponse::Known {
            principal: (),
            credential: credential(b"0123456789abcdef", 1)?,
        },
        &mut TrackingNonce {
            called: false,
            fail: false,
        },
    )?;
    let first = sasl_scram::message::ServerFirst::parse(first.as_bytes(), &resources)?;
    let final_message = format!(
        "c=biwsAAA=,r={},p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        core::str::from_utf8(first.nonce()).map_err(|_| CryptoError::Unavailable)?
    );
    assert!(matches!(
        server.receive_client_final(final_message.as_bytes()),
        Err(Error::Protocol(ProtocolError::ChannelBindingTooLarge {
            length: 2,
            maximum: 1
        }))
    ));
    Ok(())
}

#[test]
fn plus_capacity_is_rechecked_for_client_and_server_configuration() -> Result<(), Error> {
    let resources = ResourceLimits::builder()
        .max_message_bytes(120)
        .max_authorization_identity_bytes(1)
        .max_nonce_bytes(20)
        .max_channel_binding_bytes(1)
        .build()?;
    let server_config = ServerConfig::builder(Algorithm::Sha256)
        .policy(ServerPolicy::new(resources, IterationPolicy::default()))
        .build()?;
    let binding_name = "x".repeat(128);
    let binding = || -> Result<ChannelBindingMode, PolicyError> {
        Ok(ChannelBindingMode::Required(ChannelBinding::new(
            ChannelBindingName::new(binding_name.clone())?,
            ChannelBindingData::new(SecretBytes::new([1_u8].as_slice())),
            &resources,
        )?))
    };
    assert!(matches!(
        Server::with_channel_binding(server_config, binding()?),
        Err(PolicyError::InvalidResourceLimit)
    ));
    let credentials = AsciiProfile::prepare("user", SecretString::new("password"))?;
    assert!(matches!(
        ClientConfig::builder(Algorithm::Sha256)
            .credentials(credentials)
            .channel_binding(binding()?)
            .policy(ClientPolicy::new(resources, IterationPolicy::default()))
            .build(),
        Err(PolicyError::InvalidResourceLimit)
    ));
    Ok(())
}

#[cfg(feature = "sha512")]
#[test]
fn sha512_feature_enables_the_complete_server_profile() {
    assert!(ServerConfig::builder(Algorithm::Sha512).build().is_ok());
}

fn need_credential(policy: ServerPolicy) -> Result<NeedCredential, Error> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("password"))?;
    let (_, first) = Client::start(
        ClientConfig::builder(Algorithm::Sha256)
            .credentials(credentials)
            .build()?,
        &mut TrackingNonce {
            called: false,
            fail: false,
        },
    )?;
    prepare(
        Server::new(
            ServerConfig::builder(Algorithm::Sha256)
                .policy(policy)
                .build()?,
        )
        .receive_client_first(first.as_bytes())?,
    )
}

fn prepare(received: NeedIdentityPreparation) -> Result<NeedCredential, Error> {
    let (authentication_identity, authorization_identity) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )?;
    received.accept_prepared(authentication_identity, authorization_identity)
}

fn credential(salt: &[u8], count: u32) -> Result<ServerCredential, Error> {
    ServerCredential::prepare(
        Algorithm::Sha256,
        AsciiProfile::prepare_password(SecretString::new("password"))?,
        Salt::new(SecretBytes::new(salt))?,
        IterationCount::new(NonZeroU32::new(count).unwrap_or(NonZeroU32::MIN)),
    )?
    .derive()
}

fn low_cost_policy() -> Result<ServerPolicy, Error> {
    let one = NonZeroU32::MIN;
    Ok(ServerPolicy::new(
        ResourceLimits::default(),
        IterationPolicy::new(one, one)?,
    ))
}
