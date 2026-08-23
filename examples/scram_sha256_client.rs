//! Scripted RFC 7677 client proving the default public client API.

mod support;

use sasl_scram::{
    Algorithm, ChannelBindingMode, Client, ClientConfig, ClientPolicy, Rfc5802Profile, SecretString,
};

use support::{FixedNonce, ReferenceError, require_algorithm};

const CLIENT_FIRST: &[u8] = b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
const SERVER_FIRST: &[u8] =
    b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const CLIENT_FINAL: &[u8] = b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
const SERVER_FINAL: &[u8] = b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

fn main() -> Result<(), ReferenceError> {
    let credentials = Rfc5802Profile::prepare("user", SecretString::new("pencil"))?;
    let config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::Unsupported)
        .policy(ClientPolicy::default())
        .build()?;
    let mut nonce = FixedNonce::new([
        0xac, 0xea, 0x6b, 0x34, 0x67, 0xf0, 0x11, 0xb7, 0x91, 0x5a, 0x06, 0xcd, 0x12, 0x4a, 0x8e,
    ]);

    let (client, client_first) = Client::start(config, &mut nonce)?;
    require_message(client_first.as_bytes(), CLIENT_FIRST)?;

    let pending = client.receive_server_first(SERVER_FIRST)?;
    let (client, client_final) = pending.derive()?;
    require_message(client_final.as_bytes(), CLIENT_FINAL)?;

    let authenticated = client.receive_server_final(SERVER_FINAL)?;
    require_algorithm(authenticated.algorithm(), Algorithm::Sha256)
}

fn require_message(actual: &[u8], expected: &[u8]) -> Result<(), ReferenceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ReferenceError::app("unexpected SCRAM message"))
    }
}
