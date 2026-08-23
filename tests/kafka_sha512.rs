//! Kafka-compatible SCRAM-SHA-512 wire and independent derivation vectors.

#![cfg(feature = "sha512")]

use sasl_scram::{
    Algorithm, AsciiProfile, ChannelBindingMode, Client, ClientConfig, ClientPolicy, CryptoError,
    Error, NonceError, NonceSource, SecretString,
};

#[path = "../src/crypto/sha512.rs"]
mod sha512_backend;
#[path = "../src/crypto/verify.rs"]
mod verify;

const CLIENT_FIRST: &[u8] = b"n,,n=alice,r=AAECAwQFBgcICQoLDA0O";
const SERVER_FIRST: &[u8] =
    b"r=AAECAwQFBgcICQoLDA0O8PHy8/T19vf4+fr7/P3+,s=a2Fma2Etc2NyYW0tc2FsdA==,i=4096";
const CLIENT_FINAL_WITHOUT_PROOF: &[u8] = b"c=biws,r=AAECAwQFBgcICQoLDA0O8PHy8/T19vf4+fr7/P3+";
const CLIENT_FINAL: &[u8] = b"c=biws,r=AAECAwQFBgcICQoLDA0O8PHy8/T19vf4+fr7/P3+,p=NFVSNKI/oFPe4t29VNPGGAAHp6dqbpEKWayZ8N/OrTMJOf3QS9NZDtyDyaWuQchq5E3Eh9v7+K1PxdBcuCogXw==";
const SERVER_FINAL: &[u8] =
    b"v=EwjTvyhbTPw/HngKxctJfxYlDDohxDi4m7usXLan5TG8D6ufQRINMyQidzzdy432FpE2aGDFOrRITBm8Wq14nw==";

struct FixedNonce([u8; 15]);

impl NonceSource for FixedNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        if output.len() != self.0.len() {
            return Err(NonceError::unavailable());
        }
        output.copy_from_slice(&self.0);
        Ok(())
    }
}

#[test]
fn kafka_sha512_client_matches_independent_fixed_wire_vector() -> Result<(), Error> {
    assert_eq!(Algorithm::Sha512.mechanism_name(), "SCRAM-SHA-512");
    assert_eq!(
        Algorithm::Sha512.plus_mechanism_name(),
        "SCRAM-SHA-512-PLUS"
    );
    let credentials = AsciiProfile::prepare("alice", SecretString::new("alice-secret"))?;
    let config = ClientConfig::builder(Algorithm::Sha512)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::Unsupported)
        .policy(ClientPolicy::default())
        .build()?;
    let mut nonce = FixedNonce([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    let (client, first) = Client::start(config, &mut nonce)?;
    assert_eq!(first.as_bytes(), CLIENT_FIRST);
    let pending = client.receive_server_first(SERVER_FIRST)?;
    let (client, final_message) = pending.derive()?;
    assert_eq!(final_message.as_bytes(), CLIENT_FINAL);
    let authenticated = client.receive_server_final(SERVER_FINAL)?;
    assert_eq!(authenticated.algorithm(), Algorithm::Sha512);
    Ok(())
}

#[test]
fn sha512_intermediates_match_independent_values() -> Result<(), Error> {
    let salt = expected::<16>("6b61666b612d736372616d2d73616c74")?;
    let auth_message = [
        CLIENT_FIRST.split_at(3).1,
        b",",
        SERVER_FIRST,
        b",",
        CLIENT_FINAL_WITHOUT_PROOF,
    ]
    .concat();
    let salted = sha512_backend::salted_password(b"alice-secret", &salt, 4096)?;
    assert_eq!(
        salted.as_ref(),
        &expected::<64>(
            "bf390695e09f53842ce22be25328f9119b93b39cfc21aaca31978afda7f54f68a464929769985e7faf95a5fc76635f40ebb9c6291a95637e1231ab69a0dcb03c"
        )?
    );
    let client_key = sha512_backend::client_key(salted.as_ref())?;
    assert_eq!(
        client_key.as_ref(),
        &expected::<64>(
            "7015e777b28625e3e0847d04c7707a08f6ec269adb3c67dcce2954aa0892550a61008b2ea5892907791d0566b83a3b90c04ef155a0454f1ba512ae404eb27860"
        )?
    );
    let stored_key = sha512_backend::stored_key(client_key.as_ref());
    assert_eq!(
        stored_key.as_ref(),
        &expected::<64>(
            "f29fd2148b7edf96a097f430d9a54c19e2e624ba1951f4110b86bd645dbaf102896879007ee9a1c2552d099a0fe781645f3d49d1b0ad8b5990762ab506ea1949"
        )?
    );
    let client_signature = sha512_backend::client_signature(stored_key.as_ref(), &auth_message)?;
    assert_eq!(
        client_signature.as_ref(),
        &expected::<64>(
            "4440b54310b985b03e66a0b993a3bc10f6eb813db152f6d69785cd5ad75cf839683976feee5a7009a59eccc3167bf3fa240335d27bbeb7b6ead77e1cf698583f"
        )?
    );
    let proof = sha512_backend::client_proof(client_key.as_ref(), client_signature.as_ref());
    assert_eq!(
        proof.as_ref(),
        &expected::<64>(
            "34555234a23fa053dee2ddbd54d3c6180007a7a76a6e910a59ac99f0dfcead330939fdd04bd3590edc83c9a5ae41c86ae44dc487dbfbf8ad4fc5d05cb82a205f"
        )?
    );
    let server_key = sha512_backend::server_key(salted.as_ref())?;
    assert_eq!(
        server_key.as_ref(),
        &expected::<64>(
            "1d8601613d9b84a1469a4d74ecdd5a470a3245dc0b289209add65e37203af5febca9e45c5cea7392b8bec02e7b5d30b6ba334e251c963def78d3cb6d28cbd856"
        )?
    );
    let signature = sha512_backend::hmac_sha512(server_key.as_ref(), &auth_message)?;
    let expected_signature = expected::<64>(
        "1308d3bf285b4cfc3f1e780ac5cb497f16250c3a21c438b89bbbac5cb6a7e531bc0fab9f41120d332422773cddcb8df61691366860c53ab4484c19bc5aad789f",
    )?;
    assert_eq!(signature.as_ref(), &expected_signature);

    let complete = sha512_backend::derive_client(b"alice-secret", &salt, 4096, &auth_message)?;
    assert_eq!(complete.proof.as_ref(), proof.as_ref());
    assert_eq!(complete.server_signature.as_ref(), &expected_signature);
    let credential = sha512_backend::derive_server_credential(b"alice-secret", &salt, 4096)?;
    assert_eq!(credential.stored_key.as_ref(), stored_key.as_ref());
    assert_eq!(credential.server_key.as_ref(), server_key.as_ref());
    let verified = sha512_backend::verify_client_proof(
        stored_key.as_ref(),
        server_key.as_ref(),
        &auth_message,
        proof.as_ref(),
    )?;
    assert!(verified.valid);
    assert_eq!(verified.server_signature.as_ref(), &expected_signature);
    Ok(())
}

#[test]
fn sha512_backend_rejects_every_proof_and_signature_bit_mutation() -> Result<(), Error> {
    let salt = expected::<16>("6b61666b612d736372616d2d73616c74")?;
    let auth_message = [
        CLIENT_FIRST.split_at(3).1,
        b",",
        SERVER_FIRST,
        b",",
        CLIENT_FINAL_WITHOUT_PROOF,
    ]
    .concat();
    let client = sha512_backend::derive_client(b"alice-secret", &salt, 4096, &auth_message)?;
    let server = sha512_backend::derive_server_credential(b"alice-secret", &salt, 4096)?;
    for bit in 0..client.proof.len() * 8 {
        let mut mutated = *client.proof;
        mutated[bit / 8] ^= 1 << (bit % 8);
        assert!(
            !sha512_backend::verify_client_proof(
                server.stored_key.as_ref(),
                server.server_key.as_ref(),
                &auth_message,
                &mutated,
            )?
            .valid
        );
    }
    for bit in 0..client.server_signature.len() * 8 {
        let mut mutated = *client.server_signature;
        mutated[bit / 8] ^= 1 << (bit % 8);
        assert!(!verify::constant_time_eq(
            client.server_signature.as_ref(),
            &mutated
        ));
    }
    Ok(())
}

#[test]
fn sha512_synthetic_credentials_are_domain_separated() -> Result<(), Error> {
    let synthetic =
        sha512_backend::derive_synthetic_credential(b"server concealment key", b"alice", 64)?;
    assert_eq!(
        synthetic.salt.as_slice(),
        &expected::<64>(
            "e4005d1b0ac3b63967405c2192b016bf1f2176306d0745aac38df8c449c3f4759fc79ad535a794fd06886a1cc4882a1895575e1049fe7ee081cd7fc3fa6c8b62"
        )?
    );
    assert_eq!(
        synthetic.stored_key.as_ref(),
        &expected::<64>(
            "8c51e9a3f250cb9feb9fa4589c64e99fe8026afd09e7cfd2dd3f9f7fb200df9d0bc40dc4f4003d88018fe078ba16fb403907bc6d7bb503c89504c769fc3940be"
        )?
    );
    assert_eq!(
        synthetic.server_key.as_ref(),
        &expected::<64>(
            "39172de7be45360195837a97b6aa9eda047df610b5a8354f3a544645626109e0ac20d6ef2a4702ab854cebbd80cb0f17ee9b28aa70376b8c0f97a5dc7fdd4190"
        )?
    );
    Ok(())
}

fn expected<const N: usize>(hex: &str) -> Result<[u8; N], Error> {
    if hex.len() != N * 2 {
        return Err(CryptoError::Unavailable.into());
    }
    let mut output = [0_u8; N];
    for (index, destination) in output.iter_mut().enumerate() {
        let high = nibble(hex.as_bytes()[index * 2])?;
        let low = nibble(hex.as_bytes()[index * 2 + 1])?;
        *destination = high << 4 | low;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CryptoError::Unavailable.into()),
    }
}
