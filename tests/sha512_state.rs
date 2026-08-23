//! Public SHA-512 client/server, PLUS, credential, and concealment boundaries.

#![cfg(feature = "sha512")]

use core::num::{NonZeroU32, NonZeroUsize};

use sasl_scram::{
    Algorithm, AsciiProfile, AuthorizationOutcome, ChannelBinding, ChannelBindingData,
    ChannelBindingMode, ChannelBindingName, Client, ClientConfig, ConcealmentKey,
    ConcealmentProfile, CredentialResponse, CryptoError, Error, IterationCount, NeedCredential,
    NeedIdentityPreparation, NonceError, NonceSource, PolicyError, ProofResult, ResourceLimits,
    Salt, SecretBytes, SecretString, Server, ServerConfig, ServerCredential,
};
use zeroize::ZeroizeOnDrop;

struct FixedNonce(u8);

impl NonceSource for FixedNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        output.fill(self.0);
        Ok(())
    }
}

#[cfg(feature = "sha256")]
struct TrackingNonce {
    called: bool,
}

#[cfg(feature = "sha256")]
impl NonceSource for TrackingNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        self.called = true;
        output.fill(7);
        Ok(())
    }
}

#[test]
fn sha512_plus_loopback_authenticates_both_roles() -> Result<(), Error> {
    let client_credentials = AsciiProfile::prepare("alice", SecretString::new("alice-secret"))?;
    let client_config = ClientConfig::builder(Algorithm::Sha512)
        .credentials(client_credentials)
        .channel_binding(binding_mode()?)
        .build()?;
    let server_config = ServerConfig::builder(Algorithm::Sha512).build()?;
    let server = Server::with_channel_binding(server_config, binding_mode()?)?;
    let credential = credential(Algorithm::Sha512, "alice-secret")?;

    let (client, client_first) = Client::start(client_config, &mut FixedNonce(1))?;
    assert!(client_first.as_bytes().starts_with(b"p=tls-exporter,,"));
    let need = prepare(server.receive_client_first(client_first.as_bytes())?)?;
    assert_eq!(
        need.credential_request().authentication_identity().as_str(),
        "alice"
    );
    let (server, server_first) = need.resume(
        CredentialResponse::Known {
            principal: 17_u64,
            credential,
        },
        &mut FixedNonce(2),
    )?;
    let pending = client.receive_server_first(server_first.as_bytes())?;
    let (client, client_final) = pending.derive()?;
    let ProofResult::Verified(authorization) =
        server.receive_client_final(client_final.as_bytes())?
    else {
        return Err(CryptoError::Unavailable.into());
    };
    assert_eq!(*authorization.request().authenticated_principal(), 17);
    let AuthorizationOutcome::Authorized {
        authenticated,
        server_final,
    } = authorization.authorize(170_u64)?
    else {
        return Err(CryptoError::Unavailable.into());
    };
    assert_eq!(authenticated.algorithm(), Algorithm::Sha512);
    assert_eq!(*authenticated.authenticated_principal(), 17);
    assert_eq!(*authenticated.authorized_principal(), 170);
    assert_eq!(
        client
            .receive_server_final(server_final.as_bytes())?
            .algorithm(),
        Algorithm::Sha512
    );
    Ok(())
}

#[test]
fn sha512_records_enforce_algorithm_and_output_size_before_randomness() -> Result<(), Error> {
    assert!(matches!(
        ServerCredential::from_verifier_parts(
            Algorithm::Sha512,
            Salt::new(SecretBytes::new(b"0123456789abcdef".as_slice()))?,
            iterations(),
            SecretBytes::new([0_u8; 63].as_slice()),
            SecretBytes::new([0_u8; 64].as_slice()),
        ),
        Err(PolicyError::InvalidCredential)
    ));
    let valid = ServerCredential::from_verifier_parts(
        Algorithm::Sha512,
        Salt::new(SecretBytes::new(b"0123456789abcdef".as_slice()))?,
        iterations(),
        SecretBytes::new([0_u8; 64].as_slice()),
        SecretBytes::new([0_u8; 64].as_slice()),
    )?;
    assert_eq!(valid.algorithm(), Algorithm::Sha512);

    #[cfg(feature = "sha256")]
    {
        let client_credentials = AsciiProfile::prepare("alice", SecretString::new("password"))?;
        let client_config = ClientConfig::builder(Algorithm::Sha512)
            .credentials(client_credentials)
            .build()?;
        let (_, client_first) = Client::start(client_config, &mut FixedNonce(1))?;
        let server_config = ServerConfig::builder(Algorithm::Sha512).build()?;
        let need =
            prepare(Server::new(server_config).receive_client_first(client_first.as_bytes())?)?;
        let mut nonce = TrackingNonce { called: false };
        assert!(matches!(
            need.resume(
                CredentialResponse::Known {
                    principal: (),
                    credential: credential(Algorithm::Sha256, "password")?,
                },
                &mut nonce,
            ),
            Err(Error::Policy(PolicyError::InvalidCredential))
        ));
        assert!(!nonce.called);
    }
    Ok(())
}

#[test]
fn sha512_concealed_user_runs_proof_path_without_a_principal() -> Result<(), Error> {
    let client_credentials = AsciiProfile::prepare("missing", SecretString::new("password"))?;
    let client_config = ClientConfig::builder(Algorithm::Sha512)
        .credentials(client_credentials)
        .build()?;
    let server_config = ServerConfig::builder(Algorithm::Sha512).build()?;
    let (client, client_first) = Client::start(client_config, &mut FixedNonce(3))?;
    let need = prepare(Server::new(server_config).receive_client_first(client_first.as_bytes())?)?;
    let concealment = ConcealmentKey::new(SecretBytes::new([5_u8; 32].as_slice()))?;
    let response: CredentialResponse<()> = need.conceal(
        &concealment,
        ConcealmentProfile::new(NonZeroUsize::MIN.saturating_add(15), iterations()),
    )?;
    let CredentialResponse::Concealed { synthetic } = &response else {
        return Err(CryptoError::Unavailable.into());
    };
    assert_eq!(synthetic.stored_key().len(), 64);
    assert_eq!(synthetic.server_key().len(), 64);
    let (server, server_first) = need.resume(response, &mut FixedNonce(4))?;
    let pending = client.receive_server_first(server_first.as_bytes())?;
    let (_, client_final) = pending.derive()?;
    assert!(matches!(
        server.receive_client_final(client_final.as_bytes())?,
        ProofResult::Rejected { .. }
    ));
    Ok(())
}

#[test]
fn sha512_secret_states_remain_send_redacted_and_zeroize_on_drop() -> Result<(), Error> {
    fn assert_send<T: Send>() {}
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_send::<sasl_scram::PendingDerivation>();
    assert_send::<sasl_scram::AwaitingServerFinal>();
    assert_zeroize_on_drop::<sha2::Sha512>();
    assert_zeroize_on_drop::<sasl_scram::PendingDerivation>();
    assert_zeroize_on_drop::<sasl_scram::AwaitingServerFinal>();

    let credentials = AsciiProfile::prepare("alice", SecretString::new("alice-secret"))?;
    let config = ClientConfig::builder(Algorithm::Sha512)
        .credentials(credentials)
        .build()?;
    let (client, _) = Client::start(config, &mut FixedNonce(1))?;
    let pending = client.receive_server_first(b"r=AQEBAQEBAQEBAQEBAQEBserver,s=c2FsdA==,i=4096")?;
    assert_eq!(
        format!("{pending:?}"),
        "PendingDerivation { contents: \"[REDACTED]\" }"
    );
    Ok(())
}

fn binding_mode() -> Result<ChannelBindingMode, Error> {
    Ok(ChannelBindingMode::Required(ChannelBinding::new(
        ChannelBindingName::new("tls-exporter")?,
        ChannelBindingData::new(SecretBytes::new(b"sha512 channel binding".as_slice())),
        &ResourceLimits::default(),
    )?))
}

fn prepare(received: NeedIdentityPreparation) -> Result<NeedCredential, Error> {
    let (authentication_identity, authorization_identity) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )?;
    received.accept_prepared(authentication_identity, authorization_identity)
}

fn credential(algorithm: Algorithm, password: &str) -> Result<ServerCredential, Error> {
    ServerCredential::prepare(
        algorithm,
        AsciiProfile::prepare_password(SecretString::new(password))?,
        Salt::new(SecretBytes::new(b"kafka-scram-salt".as_slice()))?,
        iterations(),
    )?
    .derive()
}

fn iterations() -> IterationCount {
    IterationCount::new(NonZeroU32::new(4096).unwrap_or(NonZeroU32::MIN))
}
