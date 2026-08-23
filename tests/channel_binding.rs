//! SCRAM-SHA-256-PLUS negotiation, downgrade, transcript, and mutation coverage.

#![cfg(feature = "sha256")]

use core::num::NonZeroU32;

use sasl_scram::{
    Algorithm, AsciiProfile, AuthenticationError, AuthorizationOutcome, ChannelBinding,
    ChannelBindingData, ChannelBindingMode, ChannelBindingName, ChannelBindingOutcome, Client,
    ClientConfig, ClientPolicy, CredentialResponse, Error, IterationCount, IterationPolicy,
    NeedCredential, NeedIdentityPreparation, NonceError, NonceSource, PolicyError, ProofResult,
    ResourceLimits, Salt, SecretBytes, SecretString, Server, ServerConfig, ServerCredential,
    ServerPolicy,
};

struct FilledNonce(u8);

impl NonceSource for FilledNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        output.fill(self.0);
        Ok(())
    }
}

#[test]
fn tls_exporter_plus_loopback_authenticates_only_matching_binding() -> Result<(), Error> {
    let data = [7_u8; 32];
    let policies = low_cost_policies()?;
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let client_config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(required("tls-exporter", &data, policies.0.resources())?)
        .policy(policies.0)
        .build()?;
    let (client, client_first) = Client::start(client_config, &mut FilledNonce(0))?;
    assert!(client_first.as_bytes().starts_with(b"p=tls-exporter,,"));
    assert_eq!(
        Algorithm::Sha256.plus_mechanism_name(),
        "SCRAM-SHA-256-PLUS"
    );

    let server = Server::with_channel_binding(
        ServerConfig::builder(Algorithm::Sha256)
            .policy(policies.1)
            .build()?,
        required("tls-exporter", &data, policies.1.resources())?,
    )?;
    let need = prepare(server.receive_client_first(client_first.as_bytes())?)?;
    let (server, server_first) = need.resume(
        CredentialResponse::Known {
            principal: 17_u8,
            credential: credential()?,
        },
        &mut FilledNonce(1),
    )?;
    let (client, client_final) = client
        .receive_server_first(server_first.as_bytes())?
        .derive()?;
    let ProofResult::Verified(authorization) =
        server.receive_client_final(client_final.as_bytes())?
    else {
        return Err(AuthenticationError::InvalidProof.into());
    };
    let AuthorizationOutcome::Authorized {
        authenticated,
        server_final,
    } = authorization.authorize(17_u8)?
    else {
        return Err(AuthenticationError::AuthorizationDenied.into());
    };
    let server_binding = authenticated.properties().channel_binding();
    let ChannelBindingOutcome::Bound { name } = server_binding else {
        return Err(AuthenticationError::InvalidProof.into());
    };
    assert_eq!(name.as_str(), "tls-exporter");
    let client_authenticated = client.receive_server_final(server_final.as_bytes())?;
    let ChannelBindingOutcome::Bound { name } = client_authenticated.properties().channel_binding()
    else {
        return Err(AuthenticationError::InvalidServerSignature.into());
    };
    assert_eq!(name.as_str(), "tls-exporter");
    Ok(())
}

#[test]
fn every_one_bit_tls_exporter_mutation_fails_before_authentication() -> Result<(), Error> {
    let policies = low_cost_policies()?;
    for bit in 0..256 {
        let expected = [11_u8; 32];
        let mut received = expected;
        received[bit / 8] ^= 1 << (bit % 8);
        let (client, client_first) = start_plus_client(&received, policies.0)?;
        let server = Server::with_channel_binding(
            ServerConfig::builder(Algorithm::Sha256)
                .policy(policies.1)
                .build()?,
            required("tls-exporter", &expected, policies.1.resources())?,
        )?;
        let need = prepare(server.receive_client_first(client_first.as_bytes())?)?;
        let (server, server_first) = need.resume(
            CredentialResponse::Known {
                principal: (),
                credential: credential()?,
            },
            &mut FilledNonce(1),
        )?;
        let (_, client_final) = client
            .receive_server_first(server_first.as_bytes())?
            .derive()?;
        let ProofResult::Rejected { server_final } =
            server.receive_client_final(client_final.as_bytes())?
        else {
            return Err(AuthenticationError::InvalidProof.into());
        };
        assert_eq!(server_final.as_bytes(), b"e=channel-bindings-dont-match");
    }
    Ok(())
}

#[test]
fn plus_gs2_header_mutation_fails_before_proof_verification() -> Result<(), Error> {
    let data = [13_u8; 32];
    let policies = low_cost_policies()?;
    let (client, client_first) = start_plus_client(&data, policies.0)?;
    let server = Server::with_channel_binding(
        ServerConfig::builder(Algorithm::Sha256)
            .policy(policies.1)
            .build()?,
        required("tls-exporter", &data, policies.1.resources())?,
    )?;
    let need = prepare(server.receive_client_first(client_first.as_bytes())?)?;
    let (server, server_first) = need.resume(
        CredentialResponse::Known {
            principal: (),
            credential: credential()?,
        },
        &mut FilledNonce(1),
    )?;
    let (_, client_final) = client
        .receive_server_first(server_first.as_bytes())?
        .derive()?;
    let mut mutated = client_final.as_bytes().to_vec();
    mutated[2] = b'd';
    let ProofResult::Rejected { server_final } = server.receive_client_final(&mutated)? else {
        return Err(AuthenticationError::InvalidProof.into());
    };
    assert_eq!(server_final.as_bytes(), b"e=channel-bindings-dont-match");
    Ok(())
}

#[test]
fn negotiation_downgrades_and_wrong_binding_types_fail_before_lookup() -> Result<(), Error> {
    let policies = low_cost_policies()?;
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let y_config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::AvailableButNotNegotiated)
        .policy(policies.0)
        .build()?;
    let (_, y_first) = Client::start(y_config, &mut FilledNonce(0))?;
    let downgrade = Server::with_channel_binding(
        ServerConfig::builder(Algorithm::Sha256)
            .policy(policies.1)
            .build()?,
        ChannelBindingMode::AvailableButNotNegotiated,
    )?
    .receive_client_first(y_first.as_bytes());
    assert!(matches!(
        downgrade,
        Err(Error::Policy(PolicyError::ChannelBindingRequired))
    ));

    for first in [
        b"n,,n=user,r=nonce".as_slice(),
        b"y,,n=user,r=nonce".as_slice(),
    ] {
        let result = plus_server("tls-exporter", policies.1)?.receive_client_first(first);
        assert!(matches!(
            result,
            Err(Error::Policy(PolicyError::ChannelBindingRequired))
        ));
    }
    let wrong_type = plus_server("tls-exporter", policies.1)?
        .receive_client_first(b"p=tls-server-end-point,,n=user,r=nonce");
    assert!(matches!(
        wrong_type,
        Err(Error::Policy(PolicyError::UnsupportedChannelBindingType))
    ));
    let unbound = Server::new(
        ServerConfig::builder(Algorithm::Sha256)
            .policy(policies.1)
            .build()?,
    )
    .receive_client_first(b"p=tls-exporter,,n=user,r=nonce");
    assert!(matches!(
        unbound,
        Err(Error::Policy(PolicyError::ChannelBindingNotPermitted))
    ));
    Ok(())
}

#[test]
fn client_and_server_recheck_per_connection_binding_limit() -> Result<(), Error> {
    let broad = ResourceLimits::default();
    let binding = required("tls-exporter", &[1_u8; 32], broad)?;
    let narrow = ResourceLimits::builder()
        .max_channel_binding_bytes(16)
        .build()?;
    let config = ServerConfig::builder(Algorithm::Sha256)
        .policy(ServerPolicy::new(narrow, IterationPolicy::default()))
        .build()?;
    assert!(matches!(
        Server::with_channel_binding(config, binding),
        Err(PolicyError::ChannelBindingTooLarge {
            length: 32,
            maximum: 16
        })
    ));

    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let binding = required("tls-exporter", &[1_u8; 32], broad)?;
    let policy = ClientPolicy::new(narrow, IterationPolicy::default());
    assert!(matches!(
        ClientConfig::builder(Algorithm::Sha256)
            .credentials(credentials)
            .channel_binding(binding)
            .policy(policy)
            .build(),
        Err(PolicyError::ChannelBindingTooLarge {
            length: 32,
            maximum: 16
        })
    ));
    Ok(())
}

fn start_plus_client(
    data: &[u8],
    policy: ClientPolicy,
) -> Result<(sasl_scram::AwaitingServerFirst, sasl_scram::OutboundMessage), Error> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(required("tls-exporter", data, policy.resources())?)
        .policy(policy)
        .build()?;
    Client::start(config, &mut FilledNonce(0))
}

fn prepare(received: NeedIdentityPreparation) -> Result<NeedCredential, Error> {
    let (authentication_identity, authorization_identity) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )?;
    received.accept_prepared(authentication_identity, authorization_identity)
}

fn plus_server(name: &str, policy: ServerPolicy) -> Result<Server, Error> {
    Ok(Server::with_channel_binding(
        ServerConfig::builder(Algorithm::Sha256)
            .policy(policy)
            .build()?,
        required(name, &[5_u8; 32], policy.resources())?,
    )?)
}

fn required(
    name: &str,
    data: &[u8],
    limits: ResourceLimits,
) -> Result<ChannelBindingMode, PolicyError> {
    Ok(ChannelBindingMode::Required(ChannelBinding::new(
        ChannelBindingName::new(name)?,
        ChannelBindingData::new(SecretBytes::new(data)),
        &limits,
    )?))
}

fn credential() -> Result<ServerCredential, Error> {
    ServerCredential::prepare(
        Algorithm::Sha256,
        AsciiProfile::prepare_password(SecretString::new("pencil"))?,
        Salt::new(SecretBytes::new(b"0123456789abcdef".as_slice()))?,
        IterationCount::new(NonZeroU32::MIN),
    )?
    .derive()
}

fn low_cost_policies() -> Result<(ClientPolicy, ServerPolicy), Error> {
    let one = NonZeroU32::MIN;
    let iterations = IterationPolicy::new(one, one)?;
    let resources = ResourceLimits::default();
    Ok((
        ClientPolicy::new(resources, iterations),
        ServerPolicy::new(resources, iterations),
    ))
}
