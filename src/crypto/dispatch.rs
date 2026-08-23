//! Feature-gated dispatch across sealed complete algorithm profiles.
use crate::{Algorithm, CryptoError, SecretBytes};
pub(crate) struct ClientDerivation {
    proof: SecretBytes,
    server_signature: SecretBytes,
}
pub(crate) struct ServerCredentialDerivation {
    stored_key: SecretBytes,
    server_key: SecretBytes,
}
impl ServerCredentialDerivation {
    pub(crate) fn into_parts(self) -> (SecretBytes, SecretBytes) {
        (self.stored_key, self.server_key)
    }
}

pub(crate) struct ClientProofVerification {
    valid: bool,
    server_signature: SecretBytes,
}

impl ClientProofVerification {
    pub(crate) const fn is_valid(&self) -> bool {
        self.valid
    }

    pub(crate) fn into_server_signature(self) -> SecretBytes {
        self.server_signature
    }
}

pub(crate) struct SyntheticCredentialDerivation {
    salt: SecretBytes,
    stored_key: SecretBytes,
    server_key: SecretBytes,
}

impl SyntheticCredentialDerivation {
    pub(crate) fn into_parts(self) -> (SecretBytes, SecretBytes, SecretBytes) {
        (self.salt, self.stored_key, self.server_key)
    }
}

impl ClientDerivation {
    pub(crate) fn proof(&self) -> &[u8] {
        self.proof.expose_secret()
    }

    pub(crate) fn into_server_signature(self) -> SecretBytes {
        self.server_signature
    }
}

pub(crate) fn derive_client(
    algorithm: Algorithm,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    auth_message: &[u8],
) -> Result<ClientDerivation, CryptoError> {
    match algorithm {
        Algorithm::Sha256 => {
            #[cfg(feature = "sha256")]
            {
                let derived =
                    super::sha256::derive_client(password, salt, iterations, auth_message)?;
                Ok(owned_client(
                    derived.proof.as_ref(),
                    derived.server_signature.as_ref(),
                ))
            }
            #[cfg(not(feature = "sha256"))]
            {
                Err(CryptoError::Unavailable)
            }
        }
        #[cfg(feature = "sha512")]
        Algorithm::Sha512 => {
            let derived = super::sha512::derive_client(password, salt, iterations, auth_message)?;
            Ok(owned_client(
                derived.proof.as_ref(),
                derived.server_signature.as_ref(),
            ))
        }
    }
}

pub(crate) fn derive_server_credential(
    algorithm: Algorithm,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<ServerCredentialDerivation, CryptoError> {
    match algorithm {
        Algorithm::Sha256 => {
            #[cfg(feature = "sha256")]
            {
                let derived = super::sha256::derive_server_credential(password, salt, iterations)?;
                Ok(owned_server_credential(
                    derived.stored_key.as_ref(),
                    derived.server_key.as_ref(),
                ))
            }
            #[cfg(not(feature = "sha256"))]
            {
                Err(CryptoError::Unavailable)
            }
        }
        #[cfg(feature = "sha512")]
        Algorithm::Sha512 => {
            let derived = super::sha512::derive_server_credential(password, salt, iterations)?;
            Ok(owned_server_credential(
                derived.stored_key.as_ref(),
                derived.server_key.as_ref(),
            ))
        }
    }
}

pub(crate) fn verify_client_proof(
    algorithm: Algorithm,
    stored_key: &[u8],
    server_key: &[u8],
    auth_message: &[u8],
    proof: &[u8],
) -> Result<ClientProofVerification, CryptoError> {
    match algorithm {
        Algorithm::Sha256 => {
            #[cfg(feature = "sha256")]
            {
                let verified = super::sha256::verify_client_proof(
                    stored_key,
                    server_key,
                    auth_message,
                    proof,
                )?;
                Ok(owned_verification(
                    verified.valid,
                    verified.server_signature.as_ref(),
                ))
            }
            #[cfg(not(feature = "sha256"))]
            {
                Err(CryptoError::Unavailable)
            }
        }
        #[cfg(feature = "sha512")]
        Algorithm::Sha512 => {
            let verified =
                super::sha512::verify_client_proof(stored_key, server_key, auth_message, proof)?;
            Ok(owned_verification(
                verified.valid,
                verified.server_signature.as_ref(),
            ))
        }
    }
}

pub(crate) fn derive_synthetic_credential(
    algorithm: Algorithm,
    concealment_key: &[u8],
    authentication_identity: &[u8],
    salt_bytes: usize,
) -> Result<SyntheticCredentialDerivation, CryptoError> {
    match algorithm {
        Algorithm::Sha256 => {
            #[cfg(feature = "sha256")]
            {
                let derived = super::sha256::derive_synthetic_credential(
                    concealment_key,
                    authentication_identity,
                    salt_bytes,
                )?;
                Ok(owned_synthetic(
                    derived.salt.as_ref(),
                    derived.stored_key.as_ref(),
                    derived.server_key.as_ref(),
                ))
            }
            #[cfg(not(feature = "sha256"))]
            {
                Err(CryptoError::Unavailable)
            }
        }
        #[cfg(feature = "sha512")]
        Algorithm::Sha512 => {
            let derived = super::sha512::derive_synthetic_credential(
                concealment_key,
                authentication_identity,
                salt_bytes,
            )?;
            Ok(owned_synthetic(
                derived.salt.as_ref(),
                derived.stored_key.as_ref(),
                derived.server_key.as_ref(),
            ))
        }
    }
}

fn owned_client(proof: &[u8], server_signature: &[u8]) -> ClientDerivation {
    ClientDerivation {
        proof: SecretBytes::new(proof),
        server_signature: SecretBytes::new(server_signature),
    }
}

fn owned_server_credential(stored_key: &[u8], server_key: &[u8]) -> ServerCredentialDerivation {
    ServerCredentialDerivation {
        stored_key: SecretBytes::new(stored_key),
        server_key: SecretBytes::new(server_key),
    }
}

fn owned_verification(valid: bool, server_signature: &[u8]) -> ClientProofVerification {
    ClientProofVerification {
        valid,
        server_signature: SecretBytes::new(server_signature),
    }
}

fn owned_synthetic(
    salt: &[u8],
    stored_key: &[u8],
    server_key: &[u8],
) -> SyntheticCredentialDerivation {
    SyntheticCredentialDerivation {
        salt: SecretBytes::new(salt),
        stored_key: SecretBytes::new(stored_key),
        server_key: SecretBytes::new(server_key),
    }
}
