//! SCRAM-SHA-256 server typestate, proof, authorization, and concealment paths.
#![cfg(feature = "sha256")]

use core::num::{NonZeroU32, NonZeroUsize};

use sasl_scram::{
    Algorithm, AsciiProfile, AuthenticationError, AuthorizationOutcome, ChannelBindingOutcome,
    Client, ClientConfig, ClientPolicy, ConcealmentKey, ConcealmentProfile, CredentialResponse,
    CryptoError, Error, IterationCount, IterationPolicy, NeedCredential, NonceError, NonceSource,
    PeerError, PolicyError, ProofResult, ProtocolError, ResourceLimits, Salt, SecretBytes,
    SecretString, Server, ServerConfig, ServerCredential, ServerPolicy, message::ServerFirst,
};
struct FilledNonce(u8);
impl NonceSource for FilledNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        output.fill(self.0);
        Ok(())
    }
}
struct CountingNonce(bool);
type WireExchange = (Box<[u8]>, Box<[u8]>);
impl NonceSource for CountingNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        self.0 = true;
        output.fill(2);
        Ok(())
    }
}
#[test]
fn known_client_and_server_complete_a_sans_io_loopback() -> Result<(), Error> {
    let policy = low_cost_policies()?;
    let (client, client_first) = start_client(policy.0)?;
    let server = start_server(policy.1)?;
    let need = receive(server, client_first.as_bytes())?;
    assert_eq!(
        need.credential_request().authentication_identity().as_str(),
        "user"
    );
    let response = CredentialResponse::Known {
        principal: 42_u64,
        credential: credential("pencil", 1)?,
    };
    let (server, server_first) = need.resume(response, &mut FilledNonce(1))?;
    let pending = client.receive_server_first(server_first.as_bytes())?;
    let (client, client_final) = pending.derive()?;
    let ProofResult::Verified(authorization) =
        server.receive_client_final(client_final.as_bytes())?
    else {
        return Err(AuthenticationError::InvalidProof.into());
    };
    assert_eq!(*authorization.request().authenticated_principal(), 42);
    let AuthorizationOutcome::Authorized {
        authenticated,
        server_final,
    } = authorization.authorize("effective-user")?
    else {
        return Err(AuthenticationError::AuthorizationDenied.into());
    };
    assert_eq!(authenticated.algorithm(), Algorithm::Sha256);
    assert_eq!(*authenticated.authenticated_principal(), 42);
    assert_eq!(*authenticated.authorized_principal(), "effective-user");
    assert_eq!(
        authenticated.properties().channel_binding(),
        &ChannelBindingOutcome::Unbound
    );
    let client_authenticated = client.receive_server_final(server_final.as_bytes())?;
    assert_eq!(client_authenticated.algorithm(), Algorithm::Sha256);
    Ok(())
}
#[test]
fn invalid_proof_and_unknown_user_emit_the_same_failure_without_a_principal() -> Result<(), Error> {
    let (known_first, invalid) = rejected_exchange(false)?;
    let (concealed_first, concealed) = rejected_exchange(true)?;
    let known = ServerFirst::parse(&known_first, &ResourceLimits::default())?;
    let hidden = ServerFirst::parse(&concealed_first, &ResourceLimits::default())?;
    assert_eq!(&*invalid, b"e=invalid-proof");
    assert_eq!(invalid, concealed);
    assert_eq!((known.salt_length(), known.salt_base64().len()), (16, 24));
    assert_eq!(hidden.salt_length(), known.salt_length());
    assert_eq!(hidden.salt_base64().len(), known.salt_base64().len());
    assert_eq!(hidden.iterations(), known.iterations());
    assert_eq!(concealed_first.len(), known_first.len());
    Ok(())
}
#[test]
fn authorization_is_explicit_and_denial_emits_a_terminal_error() -> Result<(), Error> {
    let policy = low_cost_policies()?;
    let (client, client_first) = start_client(policy.0)?;
    let server = start_server(policy.1)?;
    let need = receive(server, client_first.as_bytes())?;
    let (server, server_first) = need.resume(
        CredentialResponse::Known {
            principal: 7_u8,
            credential: credential("pencil", 1)?,
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
    let AuthorizationOutcome::Denied { server_final } = authorization.deny()? else {
        return Err(AuthenticationError::AuthorizationDenied.into());
    };
    assert_eq!(server_final.as_bytes(), b"e=other-error");
    assert!(matches!(
        client.receive_server_final(server_final.as_bytes()),
        Err(Error::Authentication(AuthenticationError::PeerRejected(
            PeerError::OtherError
        )))
    ));
    Ok(())
}
#[test]
fn channel_binding_and_nonce_mismatches_fail_closed() -> Result<(), Error> {
    let policy = low_cost_policies()?;
    let (client, client_first) = start_client(policy.0)?;
    let server = start_server(policy.1)?;
    let need = receive(server, client_first.as_bytes())?;
    let (server, server_first) = need.resume(
        CredentialResponse::Known {
            principal: (),
            credential: credential("pencil", 1)?,
        },
        &mut FilledNonce(1),
    )?;
    let (_, client_final) = client
        .receive_server_first(server_first.as_bytes())?
        .derive()?;
    let mut binding_mismatch = client_final.as_bytes().to_vec();
    binding_mismatch[2..6].copy_from_slice(b"eSws");
    let ProofResult::Rejected { server_final } = server.receive_client_final(&binding_mismatch)?
    else {
        return Err(AuthenticationError::InvalidProof.into());
    };
    assert_eq!(server_final.as_bytes(), b"e=channel-bindings-dont-match");
    let (client, client_first) = start_client(policy.0)?;
    let server = start_server(policy.1)?;
    let need = receive(server, client_first.as_bytes())?;
    let (server, server_first) = need.resume(
        CredentialResponse::Known {
            principal: (),
            credential: credential("pencil", 1)?,
        },
        &mut FilledNonce(1),
    )?;
    let (_, client_final) = client
        .receive_server_first(server_first.as_bytes())?
        .derive()?;
    let mut nonce_mismatch = client_final.as_bytes().to_vec();
    let nonce_start = find(&nonce_mismatch, b",r=")?.saturating_add(3);
    nonce_mismatch[nonce_start] = b'Z';
    assert!(matches!(
        server.receive_client_final(&nonce_mismatch),
        Err(Error::Protocol(ProtocolError::InvalidNonce))
    ));
    Ok(())
}
#[test]
fn credential_policy_rejects_before_server_nonce_generation() -> Result<(), Error> {
    let (_, client_first) = start_client(low_cost_policies()?.0)?;
    let server = Server::new(ServerConfig::builder(Algorithm::Sha256).build()?);
    let need = receive(server, client_first.as_bytes())?;
    let mut nonce = CountingNonce(false);
    let result = need.resume(
        CredentialResponse::Known {
            principal: (),
            credential: credential("pencil", 1)?,
        },
        &mut nonce,
    );
    assert!(matches!(
        result,
        Err(Error::Policy(PolicyError::IterationCountTooLow))
    ));
    assert!(!nonce.0);
    Ok(())
}
#[test]
fn server_states_are_send_and_all_diagnostics_are_redacted() -> Result<(), Error> {
    assert_send::<sasl_scram::NeedCredential>();
    assert_send::<sasl_scram::NeedIdentityPreparation>();
    assert_send::<sasl_scram::AwaitingClientFinal<u64>>();
    assert_send::<sasl_scram::PendingAuthorization<u64>>();
    let policy = low_cost_policies()?;
    let (_, client_first) = start_client(policy.0)?;
    let server = start_server(policy.1)?;
    let need = receive(server, client_first.as_bytes())?;
    let request = need.credential_request();
    assert_redacted(&need);
    assert_redacted(&request);
    let (server, _) = need.resume(
        CredentialResponse::Known {
            principal: 99_u64,
            credential: credential("pencil", 1)?,
        },
        &mut FilledNonce(1),
    )?;
    assert_redacted(&server);
    Ok(())
}
fn rejected_exchange(concealed: bool) -> Result<WireExchange, Error> {
    let policy = low_cost_policies()?;
    let (client, client_first) = start_client(policy.0)?;
    let server = start_server(policy.1)?;
    let need = receive(server, client_first.as_bytes())?;
    let response = if concealed {
        let key = ConcealmentKey::new(SecretBytes::new([9_u8; 32].as_slice()))?;
        need.conceal(
            &key,
            ConcealmentProfile::new(NonZeroUsize::MIN.saturating_add(15), iteration(1)),
        )?
    } else {
        CredentialResponse::Known {
            principal: 9_u64,
            credential: credential("wrong password", 1)?,
        }
    };
    let (server, server_first) = need.resume(response, &mut FilledNonce(1))?;
    let (_, client_final) = client
        .receive_server_first(server_first.as_bytes())?
        .derive()?;
    let ProofResult::Rejected { server_final } =
        server.receive_client_final(client_final.as_bytes())?
    else {
        return Err(AuthenticationError::InvalidProof.into());
    };
    Ok((
        server_first.into_exposed_bytes(),
        server_final.into_exposed_bytes(),
    ))
}
fn start_client(
    policy: ClientPolicy,
) -> Result<(sasl_scram::AwaitingServerFirst, sasl_scram::OutboundMessage), Error> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(sasl_scram::ChannelBindingMode::Unsupported)
        .policy(policy)
        .build()?;
    Client::start(config, &mut FilledNonce(0))
}

fn start_server(policy: ServerPolicy) -> Result<Server, Error> {
    let config = ServerConfig::builder(Algorithm::Sha256)
        .policy(policy)
        .build()?;
    Ok(Server::new(config))
}
fn receive(server: Server, message: &[u8]) -> Result<NeedCredential, Error> {
    let received = server.receive_client_first(message)?;
    let (authentication_identity, authorization_identity) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )?;
    received.accept_prepared(authentication_identity, authorization_identity)
}
fn credential(password: &str, count: u32) -> Result<ServerCredential, Error> {
    ServerCredential::prepare(
        Algorithm::Sha256,
        AsciiProfile::prepare_password(SecretString::new(password))?,
        Salt::new(SecretBytes::new(b"0123456789abcdef".as_slice()))?,
        iteration(count),
    )?
    .derive()
}
fn low_cost_policies() -> Result<(ClientPolicy, ServerPolicy), Error> {
    let count = NonZeroU32::MIN;
    let iterations = IterationPolicy::new(count, count)?;
    let resources = ResourceLimits::default();
    Ok((
        ClientPolicy::new(resources, iterations),
        ServerPolicy::new(resources, iterations),
    ))
}
fn iteration(value: u32) -> IterationCount {
    IterationCount::new(NonZeroU32::new(value).unwrap_or(NonZeroU32::MIN))
}

fn find(haystack: &[u8], needle: &[u8]) -> Result<usize, Error> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .ok_or_else(|| CryptoError::Unavailable.into())
}

fn assert_send<T: Send>() {}

fn assert_redacted(value: &impl core::fmt::Debug) {
    let debug = format!("{value:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("pencil"));
    assert!(!debug.contains("user"));
}
