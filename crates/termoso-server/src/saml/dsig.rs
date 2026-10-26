//! XML-DSig enveloped signatures, the subset SAML 2.0 relies on: one
//! `ds:Signature` child of the signed element, one `ds:Reference` to that
//! element by `ID`, enveloped-signature + c14n transforms, RSA PKCS#1 v1.5 with
//! SHA-2. Trust comes only from the caller's keys (IdP metadata); any
//! `ds:KeyInfo` inside the signature is ignored.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::{Document, Node};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use super::c14n::{self, Method};
use super::sp_key::SpKey;

pub const NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const EXC_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
pub const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const DIGEST_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub const DIGEST_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

#[derive(Debug, thiserror::Error)]
pub enum DsigError {
    #[error("element has no ds:Signature")]
    Unsigned,
    #[error("malformed signature: {0}")]
    Malformed(&'static str),
    #[error("unsupported algorithm: {0}")]
    Unsupported(String),
    #[error("SHA-1 signatures are disabled")]
    Sha1Disabled,
    #[error("signed element ID is missing or not unique")]
    BadId,
    #[error("reference does not point at the signed element")]
    BadReference,
    #[error("digest mismatch")]
    Digest,
    #[error("signature does not verify with any trusted key")]
    Signature,
}

fn child<'a, 'i>(n: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| {
        c.is_element() && c.tag_name().namespace() == Some(ns) && c.tag_name().name() == name
    })
}

fn children<'a, 'i>(n: Node<'a, 'i>, ns: &str, name: &str) -> impl Iterator<Item = Node<'a, 'i>> {
    let ns = ns.to_string();
    let name = name.to_string();
    n.children().filter(move |c| {
        c.is_element()
            && c.tag_name().namespace() == Some(ns.as_str())
            && c.tag_name().name() == name
    })
}

/// Does `element` carry a direct `ds:Signature` child?
pub fn is_signed(element: Node) -> bool {
    child(element, NS, "Signature").is_some()
}

/// Verify the enveloped signature on `element` with one of `keys`.
pub fn verify_enveloped(
    doc: &Document,
    element: Node,
    keys: &[RsaPublicKey],
    allow_sha1: bool,
) -> Result<(), DsigError> {
    let mut sigs = children(element, NS, "Signature");
    let sig = sigs.next().ok_or(DsigError::Unsigned)?;
    if sigs.next().is_some() {
        return Err(DsigError::Malformed("multiple signatures"));
    }
    let signed_info = child(sig, NS, "SignedInfo").ok_or(DsigError::Malformed("no SignedInfo"))?;
    let sig_value = child(sig, NS, "SignatureValue")
        .and_then(|n| n.text())
        .ok_or(DsigError::Malformed("no SignatureValue"))?;
    let sig_bytes = STANDARD
        .decode(strip_ws(sig_value))
        .map_err(|_| DsigError::Malformed("SignatureValue base64"))?;

    let c14n_alg = child(signed_info, NS, "CanonicalizationMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .ok_or(DsigError::Malformed("no CanonicalizationMethod"))?;
    let c14n_method = Method::from_algorithm(c14n_alg, vec![])
        .ok_or_else(|| DsigError::Unsupported(c14n_alg.into()))?;
    let sig_alg = child(signed_info, NS, "SignatureMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .ok_or(DsigError::Malformed("no SignatureMethod"))?;

    // Exactly one reference, to this element by ID.
    let mut refs = children(signed_info, NS, "Reference");
    let reference = refs.next().ok_or(DsigError::Malformed("no Reference"))?;
    if refs.next().is_some() {
        return Err(DsigError::Malformed("multiple references"));
    }
    let id = element.attribute("ID").ok_or(DsigError::BadId)?;
    if id.is_empty()
        || doc
            .descendants()
            .filter(|n| n.attribute("ID") == Some(id))
            .count()
            != 1
    {
        return Err(DsigError::BadId);
    }
    let uri = reference.attribute("URI").unwrap_or("");
    if uri.strip_prefix('#') != Some(id) {
        return Err(DsigError::BadReference);
    }

    // Transforms: enveloped-signature plus at most one c14n.
    let mut enveloped = false;
    let mut ref_c14n: Option<Method> = None;
    if let Some(transforms) = child(reference, NS, "Transforms") {
        for t in children(transforms, NS, "Transform") {
            let alg = t.attribute("Algorithm").unwrap_or("");
            if alg == ENVELOPED {
                enveloped = true;
            } else if let Some(mut m) = Method::from_algorithm(alg, vec![]) {
                if ref_c14n.is_some() {
                    return Err(DsigError::Malformed("multiple c14n transforms"));
                }
                if let Some(inc) = child(t, EXC_C14N_NS, "InclusiveNamespaces") {
                    m.inclusive_prefixes = inc
                        .attribute("PrefixList")
                        .unwrap_or("")
                        .split_whitespace()
                        .map(String::from)
                        .collect();
                }
                ref_c14n = Some(m);
            } else {
                return Err(DsigError::Unsupported(alg.into()));
            }
        }
    }
    if !enveloped {
        return Err(DsigError::Malformed(
            "missing enveloped-signature transform",
        ));
    }
    let ref_c14n =
        ref_c14n.unwrap_or_else(|| Method::from_algorithm(c14n::INCLUSIVE, vec![]).unwrap());

    let digest_alg = child(reference, NS, "DigestMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .ok_or(DsigError::Malformed("no DigestMethod"))?;
    let expected = child(reference, NS, "DigestValue")
        .and_then(|n| n.text())
        .and_then(|t| STANDARD.decode(strip_ws(t)).ok())
        .ok_or(DsigError::Malformed("DigestValue"))?;

    let canon = c14n::canonicalize(element, Some(sig), &ref_c14n);
    let actual = digest(digest_alg, canon.as_bytes(), allow_sha1)?;
    if actual.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(DsigError::Digest);
    }

    let si = c14n::canonicalize(signed_info, None, &c14n_method);
    let signature = Signature::try_from(sig_bytes.as_slice()).map_err(|_| DsigError::Signature)?;
    for key in keys {
        if verify_with(sig_alg, key, si.as_bytes(), &signature, allow_sha1)? {
            return Ok(());
        }
    }
    Err(DsigError::Signature)
}

fn digest(alg: &str, data: &[u8], allow_sha1: bool) -> Result<Vec<u8>, DsigError> {
    Ok(match alg {
        DIGEST_SHA256 => Sha256::digest(data).to_vec(),
        DIGEST_SHA384 => Sha384::digest(data).to_vec(),
        DIGEST_SHA512 => Sha512::digest(data).to_vec(),
        DIGEST_SHA1 if allow_sha1 => sha1::Sha1::digest(data).to_vec(),
        DIGEST_SHA1 => return Err(DsigError::Sha1Disabled),
        other => return Err(DsigError::Unsupported(other.into())),
    })
}

/// Verify a detached signature (HTTP-Redirect binding: `SigAlg` over the
/// raw `SAMLRequest=…&RelayState=…&SigAlg=…` query) against any IdP key.
pub fn verify_detached(
    alg: &str,
    keys: &[RsaPublicKey],
    msg: &[u8],
    sig: &[u8],
    allow_sha1: bool,
) -> Result<(), DsigError> {
    let sig = Signature::try_from(sig).map_err(|_| DsigError::Malformed("bad signature"))?;
    for key in keys {
        if verify_with(alg, key, msg, &sig, allow_sha1)? {
            return Ok(());
        }
    }
    Err(DsigError::Signature)
}

fn verify_with(
    alg: &str,
    key: &RsaPublicKey,
    msg: &[u8],
    sig: &Signature,
    allow_sha1: bool,
) -> Result<bool, DsigError> {
    Ok(match alg {
        RSA_SHA256 => VerifyingKey::<Sha256>::new(key.clone())
            .verify(msg, sig)
            .is_ok(),
        RSA_SHA384 => VerifyingKey::<Sha384>::new(key.clone())
            .verify(msg, sig)
            .is_ok(),
        RSA_SHA512 => VerifyingKey::<Sha512>::new(key.clone())
            .verify(msg, sig)
            .is_ok(),
        RSA_SHA1 if allow_sha1 => VerifyingKey::<sha1::Sha1>::new(key.clone())
            .verify(msg, sig)
            .is_ok(),
        RSA_SHA1 => return Err(DsigError::Sha1Disabled),
        other => return Err(DsigError::Unsupported(other.into())),
    })
}

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Sign the element with `ID = id` in `xml` (RSA-SHA256, exclusive c14n) and
/// return the document with a `ds:Signature` inserted right after the
/// element's `saml:Issuer` child (or as its first child if there is none),
/// which is where SAML requires it. `cert_der`, when given, is embedded as
/// `ds:KeyInfo/X509Data`.
pub fn sign_enveloped(
    xml: &str,
    id: &str,
    key: &SpKey,
    cert_der: Option<&[u8]>,
) -> anyhow::Result<String> {
    let doc = Document::parse(xml)?;
    let element = doc
        .descendants()
        .find(|n| n.attribute("ID") == Some(id))
        .ok_or_else(|| anyhow::anyhow!("no element with ID {id}"))?;
    let exc = Method::from_algorithm(c14n::EXCLUSIVE, vec![]).unwrap();
    let canon = c14n::canonicalize(element, None, &exc);
    let digest = STANDARD.encode(Sha256::digest(canon.as_bytes()));
    let signed_info = format!(
        concat!(
            r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>"#,
            r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>"#,
            r##"<ds:Reference URI="#{id}">"##,
            r#"<ds:Transforms>"#,
            r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>"#,
            r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>"#,
            r#"</ds:Transforms>"#,
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>"#,
            r#"<ds:DigestValue>{digest}</ds:DigestValue>"#,
            r#"</ds:Reference>"#,
            r#"</ds:SignedInfo>"#
        ),
        id = id,
        digest = digest
    );
    let signature = key
        .sign_sha256(signed_info.as_bytes())
        .map_err(|_| anyhow::anyhow!("RSA signing failed"))?;
    let key_info = match cert_der {
        Some(der) => format!(
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
            STANDARD.encode(der)
        ),
        None => String::new(),
    };
    let sig_xml = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue>{key_info}</ds:Signature>"#,
        STANDARD.encode(signature)
    );
    // Insert after Issuer (end of its range) or right after the start tag.
    let issuer = element
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "Issuer");
    let pos = match issuer {
        Some(i) => i.range().end,
        None => {
            let start = element.range().start;
            xml[start..].find('>').map(|i| start + i + 1).unwrap()
        }
    };
    let mut out = String::with_capacity(xml.len() + sig_xml.len());
    out.push_str(&xml[..pos]);
    out.push_str(&sig_xml);
    out.push_str(&xml[pos..]);
    Ok(out)
}

/// Public key of a DER X.509 certificate (RSA only).
pub fn cert_public_key(der: &[u8]) -> anyhow::Result<RsaPublicKey> {
    use rsa::pkcs8::DecodePublicKey;
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("certificate: {e}"))?;
    RsaPublicKey::from_public_key_der(cert.public_key().raw)
        .map_err(|e| anyhow::anyhow!("certificate public key is not RSA: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SpKey {
        super::super::test_support::random_key()
    }

    const DOC: &str = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"><saml:Issuer>idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a1"><saml:Issuer>idp</saml:Issuer><saml:Subject><saml:NameID>u@x.io</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#;

    fn find<'a, 'i>(doc: &'a Document<'i>, id: &str) -> Node<'a, 'i> {
        doc.descendants()
            .find(|n| n.attribute("ID") == Some(id))
            .unwrap()
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let k = key();
        let signed = sign_enveloped(DOC, "_a1", &k, None).unwrap();
        let doc = Document::parse(&signed).unwrap();
        let a = find(&doc, "_a1");
        assert!(is_signed(a));
        assert!(!is_signed(find(&doc, "_r1")));
        verify_enveloped(&doc, a, &[k.public_key().clone()], false).unwrap();
        // Signature sits right after Issuer.
        assert!(signed.contains("</saml:Issuer><ds:Signature"));
    }

    #[test]
    fn wrong_key_and_tampering_fail() {
        let k = key();
        let signed = sign_enveloped(DOC, "_r1", &k, None).unwrap();
        let doc = Document::parse(&signed).unwrap();
        let other = key().public_key().clone();
        assert!(matches!(
            verify_enveloped(&doc, find(&doc, "_r1"), &[other], false),
            Err(DsigError::Signature)
        ));
        let tampered = signed.replace("u@x.io", "evil@x.io");
        let doc = Document::parse(&tampered).unwrap();
        assert!(matches!(
            verify_enveloped(&doc, find(&doc, "_r1"), &[k.public_key().clone()], false),
            Err(DsigError::Digest)
        ));
    }

    #[test]
    fn signature_wrapping_is_rejected() {
        let k = key();
        let signed = sign_enveloped(DOC, "_a1", &k, None).unwrap();
        // Attacker copies the signed assertion elsewhere and forges a new one
        // with the same ID: duplicate IDs must be refused.
        let doc = Document::parse(&signed).unwrap();
        let a = find(&doc, "_a1");
        let orig = &signed[a.range()];
        let forged = signed.replace(
            orig,
            &format!(
                r#"<saml:Assertion ID="_a1"><saml:Subject><saml:NameID>evil@x.io</saml:NameID></saml:Subject></saml:Assertion><samlp:Extensions>{orig}</samlp:Extensions>"#
            ),
        );
        let doc = Document::parse(&forged).unwrap();
        for n in doc
            .descendants()
            .filter(|n| n.attribute("ID") == Some("_a1"))
        {
            assert!(matches!(
                verify_enveloped(&doc, n, &[k.public_key().clone()], false),
                Err(DsigError::BadId) | Err(DsigError::Unsigned)
            ));
        }
        // Moving the signature to a different element: reference mismatch.
        let doc = Document::parse(&signed).unwrap();
        let sig_range = doc
            .descendants()
            .find(|n| n.has_tag_name((NS, "Signature")))
            .unwrap()
            .range();
        let sig_xml = signed[sig_range.clone()].to_string();
        let mut moved = signed.clone();
        moved.replace_range(sig_range, "");
        let moved = moved.replace(
            "<saml:Issuer>idp</saml:Issuer><samlp:Status>",
            &format!("<saml:Issuer>idp</saml:Issuer>{sig_xml}<samlp:Status>"),
        );
        let doc = Document::parse(&moved).unwrap();
        assert!(matches!(
            verify_enveloped(&doc, find(&doc, "_r1"), &[k.public_key().clone()], false),
            Err(DsigError::BadReference)
        ));
    }

    #[test]
    fn sha1_disabled_by_default() {
        let k = key();
        let signed = sign_enveloped(DOC, "_r1", &k, None)
            .unwrap()
            .replace(DIGEST_SHA256, DIGEST_SHA1);
        let doc = Document::parse(&signed).unwrap();
        assert!(matches!(
            verify_enveloped(&doc, find(&doc, "_r1"), &[k.public_key().clone()], false),
            Err(DsigError::Sha1Disabled)
        ));
    }
}
