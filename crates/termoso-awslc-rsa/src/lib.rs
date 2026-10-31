//! RSA private-key decryption over AWS-LC.
//!
//! The RustCrypto `rsa` crate's private-key arithmetic is not constant time
//! (RUSTSEC-2023-0071, "Marvin"). AWS-LC's is. Its safe Rust wrapper
//! (`aws-lc-rs`) exposes RSA-OAEP decryption only for a fixed digest = MGF1
//! hash, while XML Encryption lets an IdP pick them independently
//! (`xenc:EncryptionMethod` `ds:DigestMethod` vs `xenc11:MGF`), so the few
//! FFI calls needed to set them separately live here — and nowhere else in
//! the workspace.
//!
//! Everything else (key parsing, signing, signature verification) uses safe
//! Rust in the callers.

#![deny(unsafe_op_in_unsafe_fn)]

use std::mem::MaybeUninit;
use std::ptr::null_mut;

use aws_lc_sys::{
    CBS, CBS_init, EVP_MD, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new,
    EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_RSA, EVP_PKEY_bits, EVP_PKEY_decrypt, EVP_PKEY_decrypt_init, EVP_PKEY_free,
    EVP_PKEY_id, EVP_PKEY_size, EVP_parse_private_key, EVP_sha1, EVP_sha256, EVP_sha384,
    EVP_sha512, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING,
};

/// Smallest modulus accepted.
pub const MIN_BITS: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn evp_md(self) -> *const EVP_MD {
        // These return pointers to static tables and cannot fail.
        unsafe {
            match self {
                Hash::Sha1 => EVP_sha1(),
                Hash::Sha256 => EVP_sha256(),
                Hash::Sha384 => EVP_sha384(),
                Hash::Sha512 => EVP_sha512(),
            }
        }
    }
}

/// RSA encryption padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Padding {
    /// PKCS#1 v1.5 (`rsa-1_5`). Padding-oracle prone by protocol design; the
    /// caller decides whether to allow it.
    Pkcs1v15,
    /// RSAES-OAEP with an empty label; `digest` and `mgf1` may differ.
    Oaep { digest: Hash, mgf1: Hash },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("not a valid PKCS#8 private key")]
    Malformed,
    #[error("not an RSA key")]
    NotRsa,
    #[error("RSA key too small: {0} bits (minimum {MIN_BITS})")]
    TooSmall(usize),
}

/// Wrong length, wrong key or bad padding — deliberately indistinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptError;

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RSA decryption failed")
    }
}

impl std::error::Error for DecryptError {}

/// Owned `EVP_PKEY`; freed on drop.
struct Pkey(*mut EVP_PKEY);

impl Drop for Pkey {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from EVP_parse_private_key and is freed once.
        unsafe { EVP_PKEY_free(self.0) }
    }
}

// SAFETY: the key is never mutated after parsing; AWS-LC's refcounting (the
// only write EVP_PKEY_CTX_new performs on it) is atomic.
unsafe impl Send for Pkey {}
unsafe impl Sync for Pkey {}

/// Owned `EVP_PKEY_CTX`; freed on drop.
struct PkeyCtx(*mut EVP_PKEY_CTX);

impl Drop for PkeyCtx {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from EVP_PKEY_CTX_new and is freed once.
        unsafe { EVP_PKEY_CTX_free(self.0) }
    }
}

/// An RSA private key usable for decryption only.
pub struct PrivateKey {
    pkey: Pkey,
    bits: usize,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("bits", &self.bits)
            .finish()
    }
}

impl PrivateKey {
    /// Parse a PKCS#8 `PrivateKeyInfo` (DER). AWS-LC checks the key for
    /// consistency (n = p·q, CRT parameters) as part of parsing.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, KeyError> {
        let mut cbs = MaybeUninit::<CBS>::uninit();
        // SAFETY: `der` outlives `cbs`; EVP_parse_private_key reads only within
        // the CBS bounds and returns an owned pointer or null.
        let raw = unsafe {
            CBS_init(cbs.as_mut_ptr(), der.as_ptr(), der.len());
            EVP_parse_private_key(cbs.as_mut_ptr())
        };
        if raw.is_null() {
            return Err(KeyError::Malformed);
        }
        let pkey = Pkey(raw);
        // SAFETY: `pkey.0` is a live EVP_PKEY.
        if unsafe { EVP_PKEY_id(pkey.0) } != EVP_PKEY_RSA {
            return Err(KeyError::NotRsa);
        }
        // SAFETY: as above.
        let bits = usize::try_from(unsafe { EVP_PKEY_bits(pkey.0) }).unwrap_or(0);
        if bits < MIN_BITS {
            return Err(KeyError::TooSmall(bits));
        }
        Ok(Self { pkey, bits })
    }

    /// Modulus size in bits.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Unwrap `ciphertext` (exactly one RSA block) with `padding`.
    pub fn decrypt(&self, padding: Padding, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        // SAFETY: `self.pkey.0` is a live EVP_PKEY.
        let size =
            usize::try_from(unsafe { EVP_PKEY_size(self.pkey.0) }).map_err(|_| DecryptError)?;
        if size == 0 || ciphertext.len() != size {
            return Err(DecryptError);
        }
        // SAFETY: as above; a null result is checked before use.
        let ctx = PkeyCtx(unsafe { EVP_PKEY_CTX_new(self.pkey.0, null_mut()) });
        if ctx.0.is_null() {
            return Err(DecryptError);
        }
        let mut out = vec![0u8; size];
        let mut out_len = out.len();
        // SAFETY: `ctx` is a live context for an RSA key; `out` holds
        // EVP_PKEY_size bytes, the documented maximum plaintext length, and
        // `out_len` is read back only after a successful call.
        let ok = unsafe {
            EVP_PKEY_decrypt_init(ctx.0) == 1
                && match padding {
                    Padding::Pkcs1v15 => {
                        EVP_PKEY_CTX_set_rsa_padding(ctx.0, RSA_PKCS1_PADDING) == 1
                    }
                    Padding::Oaep { digest, mgf1 } => {
                        EVP_PKEY_CTX_set_rsa_padding(ctx.0, RSA_PKCS1_OAEP_PADDING) == 1
                            && EVP_PKEY_CTX_set_rsa_oaep_md(ctx.0, digest.evp_md()) == 1
                            && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.0, mgf1.evp_md()) == 1
                    }
                }
                && EVP_PKEY_decrypt(
                    ctx.0,
                    out.as_mut_ptr(),
                    &mut out_len,
                    ciphertext.as_ptr(),
                    ciphertext.len(),
                ) == 1
        };
        if !ok || out_len > out.len() {
            return Err(DecryptError);
        }
        out.truncate(out_len);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

    fn fresh() -> (RsaPrivateKey, PrivateKey) {
        let key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let der = key.to_pkcs8_der().unwrap();
        (key, PrivateKey::from_pkcs8_der(der.as_bytes()).unwrap())
    }

    fn oaep_encrypt(pk: &RsaPublicKey, digest: Hash, mgf1: Hash, msg: &[u8]) -> Vec<u8> {
        let mut rng = rand_core::OsRng;
        let padding = match (digest, mgf1) {
            (Hash::Sha1, Hash::Sha1) => Oaep::new::<sha1::Sha1>(),
            (Hash::Sha256, Hash::Sha256) => Oaep::new::<sha2::Sha256>(),
            (Hash::Sha256, Hash::Sha1) => Oaep::new_with_mgf_hash::<sha2::Sha256, sha1::Sha1>(),
            (Hash::Sha384, Hash::Sha384) => Oaep::new::<sha2::Sha384>(),
            (Hash::Sha512, Hash::Sha512) => Oaep::new::<sha2::Sha512>(),
            (Hash::Sha1, Hash::Sha256) => Oaep::new_with_mgf_hash::<sha1::Sha1, sha2::Sha256>(),
            other => panic!("no test encryptor for {other:?}"),
        };
        pk.encrypt(&mut rng, padding, msg).unwrap()
    }

    #[test]
    fn oaep_roundtrip_every_hash_combination() {
        let (key, sp) = fresh();
        let pk = key.to_public_key();
        let content_key = [0x42u8; 32];
        for (digest, mgf1) in [
            (Hash::Sha1, Hash::Sha1),
            (Hash::Sha256, Hash::Sha256),
            (Hash::Sha256, Hash::Sha1),
            (Hash::Sha384, Hash::Sha384),
            (Hash::Sha512, Hash::Sha512),
            (Hash::Sha1, Hash::Sha256),
        ] {
            let ct = oaep_encrypt(&pk, digest, mgf1, &content_key);
            let out = sp.decrypt(Padding::Oaep { digest, mgf1 }, &ct).unwrap();
            assert_eq!(out, content_key, "{digest:?}/{mgf1:?}");
        }
    }

    #[test]
    fn oaep_hash_mismatch_and_wrong_key_fail() {
        let (key, sp) = fresh();
        let ct = oaep_encrypt(&key.to_public_key(), Hash::Sha256, Hash::Sha1, b"k");
        let mismatched = [
            (Hash::Sha256, Hash::Sha256),
            (Hash::Sha1, Hash::Sha1),
            (Hash::Sha1, Hash::Sha256),
        ];
        for (digest, mgf1) in mismatched {
            assert_eq!(
                sp.decrypt(Padding::Oaep { digest, mgf1 }, &ct),
                Err(DecryptError),
                "{digest:?}/{mgf1:?}"
            );
        }
        let (_, other) = fresh();
        assert_eq!(
            other.decrypt(
                Padding::Oaep {
                    digest: Hash::Sha256,
                    mgf1: Hash::Sha1
                },
                &ct
            ),
            Err(DecryptError)
        );
    }

    #[test]
    fn malformed_ciphertext_fails() {
        let (key, sp) = fresh();
        let p = Padding::Oaep {
            digest: Hash::Sha1,
            mgf1: Hash::Sha1,
        };
        assert_eq!(sp.decrypt(p, &[]), Err(DecryptError));
        assert_eq!(sp.decrypt(p, &[0u8; 255]), Err(DecryptError));
        assert_eq!(sp.decrypt(p, &[0u8; 257]), Err(DecryptError));
        assert_eq!(sp.decrypt(p, &[0u8; 256]), Err(DecryptError));
        assert_eq!(sp.decrypt(p, &[0xffu8; 256]), Err(DecryptError));
        let mut ct = oaep_encrypt(&key.to_public_key(), Hash::Sha1, Hash::Sha1, b"k");
        ct[0] ^= 1;
        assert_eq!(sp.decrypt(p, &ct), Err(DecryptError));
    }

    #[test]
    fn pkcs1v15_roundtrip_and_no_padding_confusion() {
        let (key, sp) = fresh();
        let ct = key
            .to_public_key()
            .encrypt(&mut rand_core::OsRng, Pkcs1v15Encrypt, b"legacy")
            .unwrap();
        assert_eq!(sp.decrypt(Padding::Pkcs1v15, &ct).unwrap(), b"legacy");
        // PKCS#1 v1.5 unpadding has no integrity check: an OAEP ciphertext
        // decrypts to random bytes that look like valid v1.5 padding about
        // once in 256 keys, so only the message itself must never come back.
        let oaep = oaep_encrypt(&key.to_public_key(), Hash::Sha1, Hash::Sha1, b"legacy");
        assert_ne!(
            sp.decrypt(Padding::Pkcs1v15, &oaep).ok().as_deref(),
            Some(&b"legacy"[..])
        );
        assert_eq!(
            sp.decrypt(
                Padding::Oaep {
                    digest: Hash::Sha1,
                    mgf1: Hash::Sha1
                },
                &ct
            ),
            Err(DecryptError)
        );
    }

    #[test]
    fn key_rejections() {
        assert_eq!(
            PrivateKey::from_pkcs8_der(&[]).err(),
            Some(KeyError::Malformed)
        );
        assert_eq!(
            PrivateKey::from_pkcs8_der(&[0x30, 0x03, 0x02, 0x01, 0x00]).err(),
            Some(KeyError::Malformed)
        );
        let (_, sp) = fresh();
        assert_eq!(sp.bits(), 2048);
        let small = RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap();
        assert_eq!(
            PrivateKey::from_pkcs8_der(small.to_pkcs8_der().unwrap().as_bytes()).err(),
            Some(KeyError::TooSmall(1024))
        );
        let ec = p256_pkcs8();
        assert_eq!(
            PrivateKey::from_pkcs8_der(&ec).err(),
            Some(KeyError::NotRsa)
        );
    }

    /// A PKCS#8 P-256 key (AWS-LC parses it; we must refuse it).
    fn p256_pkcs8() -> Vec<u8> {
        let key = aws_lc_rs::signature::EcdsaKeyPair::generate(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        )
        .unwrap();
        key.to_pkcs8v1().unwrap().as_ref().to_vec()
    }
}
