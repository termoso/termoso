//! The SP's RSA private key.
//!
//! Private-key operations run in AWS-LC (constant-time RSA): decryption of
//! `EncryptedAssertion` key transport through `termoso-awslc-rsa`, and
//! AuthnRequest signing through `aws-lc-rs`. The RustCrypto `rsa` crate,
//! whose private-key arithmetic leaks timing (RUSTSEC-2023-0071), is used
//! only for parsing PEM and for public-key operations.

use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
pub use termoso_awslc_rsa::{DecryptError, Hash, Padding};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("unsupported private key PEM (expected PKCS#1 or PKCS#8)")]
    Pem,
    #[error("private key rejected: {0}")]
    Rejected(String),
    #[error(transparent)]
    Decrypt(#[from] termoso_awslc_rsa::KeyError),
}

pub struct SpKey {
    decrypt: termoso_awslc_rsa::PrivateKey,
    sign: RsaKeyPair,
    public: RsaPublicKey,
}

impl std::fmt::Debug for SpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpKey")
            .field("bits", &self.decrypt.bits())
            .finish()
    }
}

impl SpKey {
    /// Operator-supplied PEM: `BEGIN RSA PRIVATE KEY` (PKCS#1) or
    /// `BEGIN PRIVATE KEY` (PKCS#8).
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        let key = if pem.contains("BEGIN RSA PRIVATE KEY") {
            RsaPrivateKey::from_pkcs1_pem(pem).map_err(|e| KeyError::Rejected(e.to_string()))?
        } else if pem.contains("BEGIN PRIVATE KEY") {
            RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| KeyError::Rejected(e.to_string()))?
        } else {
            return Err(KeyError::Pem);
        };
        Self::from_rsa(&key)
    }

    pub fn from_rsa(key: &RsaPrivateKey) -> Result<Self, KeyError> {
        let der = key
            .to_pkcs8_der()
            .map_err(|e| KeyError::Rejected(e.to_string()))?;
        Self::from_pkcs8_der(der.as_bytes())
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, KeyError> {
        let decrypt = termoso_awslc_rsa::PrivateKey::from_pkcs8_der(der)?;
        let sign = RsaKeyPair::from_pkcs8(der).map_err(|e| KeyError::Rejected(e.to_string()))?;
        let public = RsaPublicKey::from_pkcs1_der(sign.public_key().as_ref())
            .map_err(|e| KeyError::Rejected(e.to_string()))?;
        Ok(Self {
            decrypt,
            sign,
            public,
        })
    }

    pub fn bits(&self) -> usize {
        self.decrypt.bits()
    }

    /// For matching against the SP certificate and for test IdPs that encrypt
    /// to the SP.
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    /// RSASSA-PKCS1-v1_5 with SHA-256 over `msg` (the `rsa-sha256` XML-DSig /
    /// `SigAlg` algorithm).
    pub fn sign_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, aws_lc_rs::error::Unspecified> {
        let mut sig = vec![0u8; self.sign.public_modulus_len()];
        self.sign.sign(
            &RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            msg,
            &mut sig,
        )?;
        Ok(sig)
    }

    /// Unwrap `ciphertext` (one RSA block) with `padding`.
    pub fn decrypt(&self, padding: Padding, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        self.decrypt.decrypt(padding, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::{Oaep, Pkcs1v15Encrypt};

    fn fresh() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap()
    }

    #[test]
    fn decrypts_oaep_with_independent_hashes() {
        let key = fresh();
        let sp = SpKey::from_rsa(&key).unwrap();
        let mut rng = rand_core::OsRng;
        let ct = key
            .to_public_key()
            .encrypt(
                &mut rng,
                Oaep::new_with_mgf_hash::<sha2::Sha256, sha1::Sha1>(),
                b"content key",
            )
            .unwrap();
        let padding = Padding::Oaep {
            digest: Hash::Sha256,
            mgf1: Hash::Sha1,
        };
        assert_eq!(sp.decrypt(padding, &ct).unwrap(), b"content key");
        assert_eq!(
            SpKey::from_rsa(&fresh()).unwrap().decrypt(padding, &ct),
            Err(DecryptError)
        );
        let legacy = key
            .to_public_key()
            .encrypt(&mut rng, Pkcs1v15Encrypt, b"legacy")
            .unwrap();
        assert_eq!(sp.decrypt(Padding::Pkcs1v15, &legacy).unwrap(), b"legacy");
    }

    #[test]
    fn signature_verifies_with_rsa_crate() {
        let key = fresh();
        let sp = SpKey::from_rsa(&key).unwrap();
        let sig = sp.sign_sha256(b"SAMLRequest=abc&RelayState=x").unwrap();
        assert_eq!(sig.len(), 256);
        let vk = VerifyingKey::<sha2::Sha256>::new(key.to_public_key());
        vk.verify(
            b"SAMLRequest=abc&RelayState=x",
            &Signature::try_from(sig.as_slice()).unwrap(),
        )
        .unwrap();
        assert!(
            vk.verify(
                b"SAMLRequest=abd&RelayState=x",
                &Signature::try_from(sig.as_slice()).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn pem_forms_and_rejections() {
        let key = fresh();
        let pkcs1 = key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let pkcs8 = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let a = SpKey::from_pem(&pkcs1).unwrap();
        let b = SpKey::from_pem(&pkcs8).unwrap();
        assert_eq!(a.bits(), 2048);
        assert_eq!(b.bits(), 2048);
        assert_eq!(a.public_key(), &key.to_public_key());
        assert_eq!(b.public_key(), &key.to_public_key());
        assert!(matches!(
            SpKey::from_pem("-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----"),
            Err(KeyError::Pem)
        ));
        assert!(matches!(
            SpKey::from_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
            Err(KeyError::Rejected(_))
        ));
        assert!(matches!(
            SpKey::from_pkcs8_der(&[0x30, 0x03, 0x02, 0x01, 0x00]),
            Err(KeyError::Decrypt(termoso_awslc_rsa::KeyError::Malformed))
        ));
        let small = RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap();
        assert!(matches!(
            SpKey::from_rsa(&small),
            Err(KeyError::Decrypt(termoso_awslc_rsa::KeyError::TooSmall(
                1024
            )))
        ));
    }
}
