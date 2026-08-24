//! In-memory server proving caller-owned lookup and authorization continuations.

mod support;

use core::num::{NonZeroU32, NonZeroUsize};

use sasl_scram::{
    Algorithm, AsciiProfile, AuthorizationOutcome, AuthorizationRequest, Client, ClientConfig,
    ConcealmentKey, ConcealmentProfile, CredentialResponse, IterationCount, NeedCredential,
    ProofResult, Rfc5802Profile, Salt, SecretBytes, SecretString, Server, ServerConfig,
    ServerCredential,
};

use support::{FixedNonce, ReferenceError, require_algorithm};

struct CredentialStore {
    known: Option<ServerCredential>,
    concealment: ConcealmentKey,
}

impl CredentialStore {
    fn new() -> Result<Self, ReferenceError> {
        let password = Rfc5802Profile::prepare_password(SecretString::new("pencil"))?;
        let pending = ServerCredential::prepare(
            Algorithm::Sha256,
            password,
            Salt::new(SecretBytes::new(b"reference server salt".as_slice()))?,
            iterations(),
        )?;
        Ok(Self {
            known: Some(pending.derive()?),
            concealment: ConcealmentKey::new(SecretBytes::new([0x5a_u8; 32].as_slice()))?,
        })
    }

    fn lookup(
        &mut self,
        need: &NeedCredential,
    ) -> Result<CredentialResponse<&'static str>, ReferenceError> {
        let identity = need.credential_request().authentication_identity();
        if identity.as_str() == "user" {
            let credential = self
                .known
                .take()
                .ok_or_else(|| ReferenceError::app("reference credential was already consumed"))?;
            Ok(CredentialResponse::Known {
                principal: "example-user",
                credential,
            })
        } else {
            Ok(need.conceal(
                &self.concealment,
                ConcealmentProfile::new(NonZeroUsize::MIN.saturating_add(15), iterations()),
            )?)
        }
    }
}

fn main() -> Result<(), ReferenceError> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let client_config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(sasl_scram::ChannelBindingMode::Unsupported)
        .build()?;
    let server_config = ServerConfig::builder(Algorithm::Sha256).build()?;
    let mut store = CredentialStore::new()?;

    let (client, client_first) = Client::start(client_config, &mut FixedNonce::new([1_u8; 15]))?;
    let received = Server::new(server_config).receive_client_first(client_first.as_bytes())?;
    let (authentication_identity, authorization_identity) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )?;
    let need = received.accept_prepared(authentication_identity, authorization_identity)?;
    let response = store.lookup(&need)?;
    let (server, server_first) = need.resume(response, &mut FixedNonce::new([2_u8; 15]))?;

    let (client, client_final) = client
        .receive_server_first(server_first.as_bytes())?
        .derive()?;
    let ProofResult::Verified(authorization) =
        server.receive_client_final(client_final.as_bytes())?
    else {
        return Err(ReferenceError::app("unexpected proof outcome"));
    };
    let authorized_principal = authorize(authorization.request())
        .ok_or_else(|| ReferenceError::app("authorization denied"))?;
    let AuthorizationOutcome::Authorized {
        authenticated,
        server_final,
    } = authorization.authorize(authorized_principal)?
    else {
        return Err(ReferenceError::app("unexpected authenticated principal"));
    };

    require_algorithm(authenticated.algorithm(), Algorithm::Sha256)?;
    if *authenticated.authenticated_principal() != "example-user"
        || *authenticated.authorized_principal() != "application-user"
    {
        return Err(ReferenceError::app("unexpected authenticated identity"));
    }
    let client_authenticated = client.receive_server_final(server_final.as_bytes())?;
    require_algorithm(client_authenticated.algorithm(), Algorithm::Sha256)
}

fn authorize(request: AuthorizationRequest<'_, &'static str>) -> Option<&'static str> {
    if request.authentication_identity().as_str() == "user"
        && request.authorization_identity().is_none()
        && *request.authenticated_principal() == "example-user"
    {
        Some("application-user")
    } else {
        None
    }
}

fn iterations() -> IterationCount {
    IterationCount::new(NonZeroU32::new(4096).unwrap_or(NonZeroU32::MIN))
}
