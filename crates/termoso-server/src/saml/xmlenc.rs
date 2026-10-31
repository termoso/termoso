//! XML Encryption for `saml:EncryptedAssertion`: RSA key transport
//! (`rsa-1_5`, `rsa-oaep-mgf1p`, `rsa-oaep`) wrapping an AES-CBC or AES-GCM
//! content key. Returns the decrypted `saml:Assertion` XML re-wrapped with
//! the namespaces that were in scope where the encrypted element sat, so the
//! fragment parses (and canonicalizes) exactly as the IdP signed it.

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Node;
use rsa::Oaep;

use super::sp_key::{Hash, Padding, SpKey};

pub const NS: &str = "http://www.w3.org/2001/04/xmlenc#";
const DS_NS: &str = super::dsig::NS;

const RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
const AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const AES192_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
const AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const NS11: &str = "http://www.w3.org/2009/xmlenc11#";
const MGF1_SHA1: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha1";
const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
const MGF1_SHA384: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha384";
const MGF1_SHA512: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha512";

fn digest_hash(uri: &str) -> Option<Hash> {
    match uri {
        super::dsig::DIGEST_SHA1 => Some(Hash::Sha1),
        super::dsig::DIGEST_SHA256 => Some(Hash::Sha256),
        super::dsig::DIGEST_SHA384 => Some(Hash::Sha384),
        super::dsig::DIGEST_SHA512 => Some(Hash::Sha512),
        _ => None,
    }
}

fn mgf1_hash(uri: &str) -> Option<Hash> {
    match uri {
        MGF1_SHA1 => Some(Hash::Sha1),
        MGF1_SHA256 => Some(Hash::Sha256),
        MGF1_SHA384 => Some(Hash::Sha384),
        MGF1_SHA512 => Some(Hash::Sha512),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncError {
    #[error("malformed EncryptedAssertion: {0}")]
    Malformed(&'static str),
    #[error("unsupported encryption algorithm: {0}")]
    Unsupported(String),
    #[error("decryption failed")]
    Decrypt,
}

fn child<'a, 'i>(n: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| {
        c.is_element() && c.tag_name().namespace() == Some(ns) && c.tag_name().name() == name
    })
}

fn cipher_value(n: Node) -> Result<Vec<u8>, EncError> {
    let v = child(n, NS, "CipherData")
        .and_then(|d| child(d, NS, "CipherValue"))
        .and_then(|v| v.text())
        .ok_or(EncError::Malformed("CipherValue"))?;
    STANDARD
        .decode(v.chars().filter(|c| !c.is_whitespace()).collect::<String>())
        .map_err(|_| EncError::Malformed("CipherValue base64"))
}

/// Decrypt `saml:EncryptedAssertion` → assertion XML text. PKCS#1 v1.5 key
/// transport (`rsa-1_5`, padding-oracle prone) is only accepted with
/// `allow_legacy`.
pub fn decrypt_assertion(
    encrypted: Node,
    sp_key: &SpKey,
    allow_legacy: bool,
) -> Result<String, EncError> {
    let data = child(encrypted, NS, "EncryptedData").ok_or(EncError::Malformed("EncryptedData"))?;
    let data_alg = child(data, NS, "EncryptionMethod")
        .and_then(|m| m.attribute("Algorithm"))
        .ok_or(EncError::Malformed("EncryptionMethod"))?;

    // The EncryptedKey lives in ds:KeyInfo, or next to EncryptedData (possibly
    // referenced via ds:RetrievalMethod). Any of those placements is accepted.
    let key_info = child(data, DS_NS, "KeyInfo");
    let enc_key = key_info
        .and_then(|k| child(k, NS, "EncryptedKey"))
        .or_else(|| {
            let uri = key_info
                .and_then(|k| child(k, DS_NS, "RetrievalMethod"))
                .and_then(|r| r.attribute("URI"))
                .and_then(|u| u.strip_prefix('#'));
            encrypted.children().find(|c| {
                c.is_element()
                    && c.tag_name().namespace() == Some(NS)
                    && c.tag_name().name() == "EncryptedKey"
                    && uri.is_none_or(|u| c.attribute("Id") == Some(u))
            })
        })
        .ok_or(EncError::Malformed("EncryptedKey"))?;
    let key_method = child(enc_key, NS, "EncryptionMethod")
        .ok_or(EncError::Malformed("key EncryptionMethod"))?;
    let key_alg = key_method.attribute("Algorithm").unwrap_or("");
    let wrapped = cipher_value(enc_key)?;

    let padding = match key_alg {
        RSA_1_5 if allow_legacy => Padding::Pkcs1v15,
        RSA_OAEP_MGF1P => Padding::Oaep {
            digest: Hash::Sha1,
            mgf1: Hash::Sha1,
        },
        RSA_OAEP => {
            // xmlenc11: DigestMethod defaults to SHA-1, MGF to MGF1-SHA1.
            let digest = child(key_method, DS_NS, "DigestMethod")
                .and_then(|d| d.attribute("Algorithm"))
                .unwrap_or(super::dsig::DIGEST_SHA1);
            let mgf = child(key_method, NS11, "MGF")
                .and_then(|d| d.attribute("Algorithm"))
                .unwrap_or(MGF1_SHA1);
            match (digest_hash(digest), mgf1_hash(mgf)) {
                (Some(digest), Some(mgf1)) => Padding::Oaep { digest, mgf1 },
                _ => return Err(EncError::Unsupported(format!("{key_alg} {digest} {mgf}"))),
            }
        }
        other => return Err(EncError::Unsupported(other.into())),
    };
    let content_key = sp_key
        .decrypt(padding, &wrapped)
        .map_err(|_| EncError::Decrypt)?;

    let ciphertext = cipher_value(data)?;
    let plain = match data_alg {
        AES128_CBC => cbc_decrypt::<aes::Aes128>(&content_key, &ciphertext)?,
        AES192_CBC => cbc_decrypt::<aes::Aes192>(&content_key, &ciphertext)?,
        AES256_CBC => cbc_decrypt::<aes::Aes256>(&content_key, &ciphertext)?,
        AES128_GCM => gcm_decrypt::<Aes128Gcm>(&content_key, &ciphertext)?,
        AES256_GCM => gcm_decrypt::<Aes256Gcm>(&content_key, &ciphertext)?,
        other => return Err(EncError::Unsupported(other.into())),
    };
    let fragment = String::from_utf8(plain).map_err(|_| EncError::Decrypt)?;
    let fragment = fragment.trim_start_matches('\u{feff}').trim();

    // Re-establish the namespaces the fragment inherited from the response.
    let mut wrap = String::from("<w");
    for ns in encrypted.namespaces() {
        match ns.name() {
            Some(p) => {
                wrap.push_str(&format!(" xmlns:{p}=\"{}\"", esc(ns.uri())));
            }
            None => wrap.push_str(&format!(" xmlns=\"{}\"", esc(ns.uri()))),
        }
    }
    wrap.push('>');
    wrap.push_str(fragment);
    wrap.push_str("</w>");
    Ok(wrap)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
}

fn cbc_decrypt<C>(key: &[u8], data: &[u8]) -> Result<Vec<u8>, EncError>
where
    C: aes::cipher::BlockCipher + aes::cipher::BlockDecrypt + aes::cipher::KeyInit,
{
    let (iv, body) = data.split_at_checked(16).ok_or(EncError::Decrypt)?;
    if body.is_empty() || body.len() % 16 != 0 {
        return Err(EncError::Decrypt);
    }
    let dec = cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| EncError::Decrypt)?;
    let mut buf = body.to_vec();
    dec.decrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|_| EncError::Decrypt)?;
    // XML Encryption padding: last byte = number of padding bytes (1..=16),
    // the others are arbitrary (not PKCS#7).
    let pad = *buf.last().ok_or(EncError::Decrypt)? as usize;
    if pad == 0 || pad > 16 || pad > buf.len() {
        return Err(EncError::Decrypt);
    }
    buf.truncate(buf.len() - pad);
    Ok(buf)
}

fn gcm_decrypt<A>(key: &[u8], data: &[u8]) -> Result<Vec<u8>, EncError>
where
    A: Aead + KeyInit,
{
    let (iv, body) = data.split_at_checked(12).ok_or(EncError::Decrypt)?;
    let cipher = A::new_from_slice(key).map_err(|_| EncError::Decrypt)?;
    cipher
        .decrypt(iv.into(), body)
        .map_err(|_| EncError::Decrypt)
}

/// How a test IdP wraps the content key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTransport {
    /// `rsa-oaep-mgf1p` (SHA-1 / MGF1-SHA1), what most IdPs send.
    OaepMgf1p,
    /// `rsa-oaep` with explicit `DigestMethod` and `xenc11:MGF`.
    Oaep { digest: Hash, mgf1: Hash },
    /// `rsa-oaep` with a SHA-256 digest and no `MGF` element (MGF1-SHA1 by
    /// default), as Apache Santuario-based IdPs emit.
    OaepSha256DefaultMgf,
    /// `rsa-1_5`.
    Pkcs1v15,
}

/// Encrypt an assertion for the SP (AES-256-CBC + RSA-OAEP-MGF1P): what a
/// test IdP needs to exercise the decrypt path.
pub fn encrypt_assertion(assertion_xml: &str, sp_public: &rsa::RsaPublicKey) -> String {
    encrypt_assertion_with(assertion_xml, sp_public, KeyTransport::OaepMgf1p)
}

pub fn encrypt_assertion_with(
    assertion_xml: &str,
    sp_public: &rsa::RsaPublicKey,
    transport: KeyTransport,
) -> String {
    use aes::cipher::BlockEncryptMut;
    let mut rng = rand_core::OsRng;
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let mut iv = [0u8; 16];
    rand::fill(&mut iv);
    let mut plain = assertion_xml.as_bytes().to_vec();
    let pad = 16 - (plain.len() % 16);
    plain.extend(std::iter::repeat_n(0u8, pad - 1));
    plain.push(pad as u8);
    let enc = cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into());
    let n = plain.len();
    let ct = enc
        .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut plain, n)
        .unwrap()
        .to_vec();
    let mut data = iv.to_vec();
    data.extend(ct);
    fn digest_uri(h: Hash) -> &'static str {
        match h {
            Hash::Sha1 => super::dsig::DIGEST_SHA1,
            Hash::Sha256 => super::dsig::DIGEST_SHA256,
            Hash::Sha384 => super::dsig::DIGEST_SHA384,
            Hash::Sha512 => super::dsig::DIGEST_SHA512,
        }
    }
    fn mgf_uri(h: Hash) -> &'static str {
        match h {
            Hash::Sha1 => MGF1_SHA1,
            Hash::Sha256 => MGF1_SHA256,
            Hash::Sha384 => MGF1_SHA384,
            Hash::Sha512 => MGF1_SHA512,
        }
    }
    fn oaep(digest: Hash, mgf1: Hash) -> Oaep {
        match (digest, mgf1) {
            (Hash::Sha1, Hash::Sha1) => Oaep::new::<sha1::Sha1>(),
            (Hash::Sha256, Hash::Sha256) => Oaep::new::<sha2::Sha256>(),
            (Hash::Sha384, Hash::Sha384) => Oaep::new::<sha2::Sha384>(),
            (Hash::Sha512, Hash::Sha512) => Oaep::new::<sha2::Sha512>(),
            (Hash::Sha256, Hash::Sha1) => Oaep::new_with_mgf_hash::<sha2::Sha256, sha1::Sha1>(),
            (Hash::Sha1, Hash::Sha256) => Oaep::new_with_mgf_hash::<sha1::Sha1, sha2::Sha256>(),
            other => panic!("no test encryptor for {other:?}"),
        }
    }
    let (wrapped, method) = match transport {
        KeyTransport::OaepMgf1p => (
            sp_public
                .encrypt(&mut rng, oaep(Hash::Sha1, Hash::Sha1), &key)
                .unwrap(),
            format!(r#"<xenc:EncryptionMethod Algorithm="{RSA_OAEP_MGF1P}"/>"#),
        ),
        KeyTransport::Oaep { digest, mgf1 } => (
            sp_public
                .encrypt(&mut rng, oaep(digest, mgf1), &key)
                .unwrap(),
            format!(
                concat!(
                    r#"<xenc:EncryptionMethod Algorithm="{alg}">"#,
                    r#"<ds:DigestMethod Algorithm="{digest}"/>"#,
                    r#"<xenc11:MGF xmlns:xenc11="{ns11}" Algorithm="{mgf}"/>"#,
                    r#"</xenc:EncryptionMethod>"#
                ),
                alg = RSA_OAEP,
                digest = digest_uri(digest),
                ns11 = NS11,
                mgf = mgf_uri(mgf1),
            ),
        ),
        KeyTransport::OaepSha256DefaultMgf => (
            sp_public
                .encrypt(&mut rng, oaep(Hash::Sha256, Hash::Sha1), &key)
                .unwrap(),
            format!(
                concat!(
                    r#"<xenc:EncryptionMethod Algorithm="{alg}">"#,
                    r#"<ds:DigestMethod Algorithm="{digest}"/>"#,
                    r#"</xenc:EncryptionMethod>"#
                ),
                alg = RSA_OAEP,
                digest = super::dsig::DIGEST_SHA256,
            ),
        ),
        KeyTransport::Pkcs1v15 => (
            sp_public
                .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &key)
                .unwrap(),
            format!(r#"<xenc:EncryptionMethod Algorithm="{RSA_1_5}"/>"#),
        ),
    };
    format!(
        concat!(
            r#"<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">"#,
            r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">"#,
            r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>"#,
            r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>"#,
            "{method}",
            r#"<xenc:CipherData><xenc:CipherValue>{k}</xenc:CipherValue></xenc:CipherData>"#,
            r#"</xenc:EncryptedKey></ds:KeyInfo>"#,
            r#"<xenc:CipherData><xenc:CipherValue>{d}</xenc:CipherValue></xenc:CipherData>"#,
            r#"</xenc:EncryptedData></saml:EncryptedAssertion>"#
        ),
        method = method,
        k = STANDARD.encode(wrapped),
        d = STANDARD.encode(data)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;

    const ASSERTION: &str = r#"<saml:Assertion ID="_a" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>idp</saml:Issuer></saml:Assertion>"#;

    fn keys() -> (RsaPrivateKey, SpKey) {
        let key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let sp = SpKey::from_rsa(&key).unwrap();
        (key, sp)
    }

    #[test]
    fn roundtrip() {
        let (key, sp) = keys();
        let enc = encrypt_assertion(ASSERTION, &key.to_public_key());
        let doc = roxmltree::Document::parse(&enc).unwrap();
        let out = decrypt_assertion(doc.root_element(), &sp, false).unwrap();
        assert!(out.contains(ASSERTION));
        let (_, wrong) = keys();
        assert!(matches!(
            decrypt_assertion(doc.root_element(), &wrong, false),
            Err(EncError::Decrypt)
        ));
    }

    #[test]
    fn every_oaep_variant_roundtrips() {
        let (key, sp) = keys();
        let pk = key.to_public_key();
        let variants = [
            KeyTransport::OaepMgf1p,
            KeyTransport::OaepSha256DefaultMgf,
            KeyTransport::Oaep {
                digest: Hash::Sha1,
                mgf1: Hash::Sha1,
            },
            KeyTransport::Oaep {
                digest: Hash::Sha256,
                mgf1: Hash::Sha256,
            },
            KeyTransport::Oaep {
                digest: Hash::Sha256,
                mgf1: Hash::Sha1,
            },
            KeyTransport::Oaep {
                digest: Hash::Sha384,
                mgf1: Hash::Sha384,
            },
            KeyTransport::Oaep {
                digest: Hash::Sha512,
                mgf1: Hash::Sha512,
            },
        ];
        for v in variants {
            let enc = encrypt_assertion_with(ASSERTION, &pk, v);
            let doc = roxmltree::Document::parse(&enc).unwrap();
            let out = decrypt_assertion(doc.root_element(), &sp, false)
                .unwrap_or_else(|e| panic!("{v:?}: {e}"));
            assert!(out.contains(ASSERTION), "{v:?}");
        }
    }

    #[test]
    fn oaep_parameters_must_match_the_ciphertext() {
        let (key, sp) = keys();
        // Wrapped with SHA-256/MGF1-SHA1 but declared SHA-256/MGF1-SHA256.
        let enc = encrypt_assertion_with(ASSERTION, &key.to_public_key(), KeyTransport::OaepSha256DefaultMgf)
            .replace(
                "</xenc:EncryptionMethod>",
                &format!(r#"<xenc11:MGF xmlns:xenc11="{NS11}" Algorithm="{MGF1_SHA256}"/></xenc:EncryptionMethod>"#),
            );
        let doc = roxmltree::Document::parse(&enc).unwrap();
        assert!(matches!(
            decrypt_assertion(doc.root_element(), &sp, false),
            Err(EncError::Decrypt)
        ));
    }

    #[test]
    fn unknown_oaep_parameters_are_unsupported() {
        let (key, sp) = keys();
        let enc = encrypt_assertion_with(
            ASSERTION,
            &key.to_public_key(),
            KeyTransport::Oaep {
                digest: Hash::Sha256,
                mgf1: Hash::Sha256,
            },
        );
        let bad_mgf = enc.replace(MGF1_SHA256, "urn:mgf:md5");
        let doc = roxmltree::Document::parse(&bad_mgf).unwrap();
        assert!(matches!(
            decrypt_assertion(doc.root_element(), &sp, false),
            Err(EncError::Unsupported(_))
        ));
        let bad_digest = enc.replace(super::super::dsig::DIGEST_SHA256, "urn:digest:md5");
        let doc = roxmltree::Document::parse(&bad_digest).unwrap();
        assert!(matches!(
            decrypt_assertion(doc.root_element(), &sp, false),
            Err(EncError::Unsupported(_))
        ));
    }

    #[test]
    fn truncated_or_corrupted_wrapped_key_fails_closed() {
        let (key, sp) = keys();
        let enc = encrypt_assertion(ASSERTION, &key.to_public_key());
        let doc = roxmltree::Document::parse(&enc).unwrap();
        let ek = doc
            .descendants()
            .find(|n| n.tag_name().name() == "EncryptedKey")
            .unwrap();
        let wrapped = cipher_value(ek).unwrap();
        let b64 = STANDARD.encode(&wrapped);
        for bad in [
            STANDARD.encode(&wrapped[..wrapped.len() - 1]),
            STANDARD.encode([wrapped.as_slice(), &[0u8]].concat()),
            STANDARD.encode(
                wrapped
                    .iter()
                    .enumerate()
                    .map(|(i, b)| if i == 7 { b ^ 0x80 } else { *b })
                    .collect::<Vec<_>>(),
            ),
            String::new(),
        ] {
            let tampered = enc.replacen(&b64, &bad, 1);
            let doc = roxmltree::Document::parse(&tampered).unwrap();
            assert!(matches!(
                decrypt_assertion(doc.root_element(), &sp, false),
                Err(EncError::Decrypt) | Err(EncError::Malformed(_))
            ));
        }
    }

    #[test]
    fn rsa15_key_transport_requires_legacy_flag() {
        let (key, sp) = keys();
        let enc = encrypt_assertion_with(ASSERTION, &key.to_public_key(), KeyTransport::Pkcs1v15);
        let doc = roxmltree::Document::parse(&enc).unwrap();
        assert!(matches!(
            decrypt_assertion(doc.root_element(), &sp, false),
            Err(EncError::Unsupported(_))
        ));
        let out = decrypt_assertion(doc.root_element(), &sp, true).unwrap();
        assert!(out.contains(ASSERTION));
        // An OAEP-wrapped key declared as rsa-1_5 fails closed.
        let mislabeled =
            encrypt_assertion(ASSERTION, &key.to_public_key()).replace(RSA_OAEP_MGF1P, RSA_1_5);
        let doc = roxmltree::Document::parse(&mislabeled).unwrap();
        assert!(matches!(
            decrypt_assertion(doc.root_element(), &sp, true),
            Err(EncError::Decrypt)
        ));
    }
}
