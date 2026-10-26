//! SAML 2.0 metadata: parse what the SP needs from an IdP `EntityDescriptor`
//! and render the SP's own descriptor for the IdP administrator.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::{Document, Node};
use rsa::RsaPublicKey;

use super::dsig;

pub const NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub const NAMEID_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

#[derive(Debug, Clone)]
pub struct IdpMetadata {
    pub entity_id: String,
    /// SingleSignOnService for HTTP-Redirect (preferred) and HTTP-POST.
    pub sso_redirect: Option<String>,
    pub sso_post: Option<String>,
    /// SingleLogoutService for HTTP-Redirect and HTTP-POST; absent when the
    /// IdP does not do Single Logout.
    pub slo_redirect: Option<String>,
    pub slo_post: Option<String>,
    pub want_authn_requests_signed: bool,
    pub signing_keys: Vec<RsaPublicKey>,
    /// DER certificates the keys came from (for diagnostics/expiry logging).
    pub signing_certs: Vec<Vec<u8>>,
}

fn elements<'a, 'i>(
    n: Node<'a, 'i>,
    ns: &'static str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'i>> {
    n.children().filter(move |c| {
        c.is_element() && c.tag_name().namespace() == Some(ns) && c.tag_name().name() == name
    })
}

/// Parse IdP metadata. `entity_id` selects one descriptor out of an
/// `EntitiesDescriptor` aggregate; otherwise the first IdP wins.
pub fn parse_idp(xml: &str, entity_id: Option<&str>) -> anyhow::Result<IdpMetadata> {
    let doc = Document::parse(xml)?;
    let root = doc.root_element();
    let mut descriptors: Vec<Node> = Vec::new();
    collect_entities(root, &mut descriptors);
    let chosen = descriptors
        .iter()
        .copied()
        .filter(|e| elements(*e, NS, "IDPSSODescriptor").next().is_some())
        .find(|e| entity_id.is_none_or(|want| e.attribute("entityID") == Some(want)))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "metadata has no IDPSSODescriptor{}",
                match entity_id {
                    Some(id) => format!(" for entityID {id}"),
                    None => String::new(),
                }
            )
        })?;
    let entity = chosen
        .attribute("entityID")
        .ok_or_else(|| anyhow::anyhow!("EntityDescriptor without entityID"))?
        .to_string();
    let idp = elements(chosen, NS, "IDPSSODescriptor").next().unwrap();
    let want_signed = idp
        .attribute("WantAuthnRequestsSigned")
        .is_some_and(|v| v == "true" || v == "1");

    let mut sso_redirect = None;
    let mut sso_post = None;
    for s in elements(idp, NS, "SingleSignOnService") {
        match (s.attribute("Binding"), s.attribute("Location")) {
            (Some(BINDING_REDIRECT), Some(loc)) if sso_redirect.is_none() => {
                sso_redirect = Some(loc.to_string())
            }
            (Some(BINDING_POST), Some(loc)) if sso_post.is_none() => {
                sso_post = Some(loc.to_string())
            }
            _ => {}
        }
    }
    if sso_redirect.is_none() && sso_post.is_none() {
        anyhow::bail!("IdP metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService");
    }
    let mut slo_redirect = None;
    let mut slo_post = None;
    for s in elements(idp, NS, "SingleLogoutService") {
        match (s.attribute("Binding"), s.attribute("Location")) {
            (Some(BINDING_REDIRECT), Some(loc)) if slo_redirect.is_none() => {
                slo_redirect = Some(loc.to_string())
            }
            (Some(BINDING_POST), Some(loc)) if slo_post.is_none() => {
                slo_post = Some(loc.to_string())
            }
            _ => {}
        }
    }

    let mut signing_keys = Vec::new();
    let mut signing_certs = Vec::new();
    for kd in elements(idp, NS, "KeyDescriptor") {
        if kd.attribute("use").is_some_and(|u| u == "encryption") {
            continue;
        }
        for cert in kd.descendants().filter(|n| {
            n.tag_name().namespace() == Some(dsig::NS) && n.tag_name().name() == "X509Certificate"
        }) {
            let b64: String = cert
                .text()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let der = STANDARD
                .decode(&b64)
                .map_err(|e| anyhow::anyhow!("IdP certificate base64: {e}"))?;
            let key = dsig::cert_public_key(&der)?;
            signing_keys.push(key);
            signing_certs.push(der);
        }
    }
    if signing_keys.is_empty() {
        anyhow::bail!("IdP metadata has no signing certificate");
    }
    Ok(IdpMetadata {
        entity_id: entity,
        sso_redirect,
        sso_post,
        slo_redirect,
        slo_post,
        want_authn_requests_signed: want_signed,
        signing_keys,
        signing_certs,
    })
}

fn collect_entities<'a, 'i>(n: Node<'a, 'i>, out: &mut Vec<Node<'a, 'i>>) {
    if n.tag_name().namespace() == Some(NS) {
        match n.tag_name().name() {
            "EntityDescriptor" => out.push(n),
            "EntitiesDescriptor" => {
                for c in n.children().filter(|c| c.is_element()) {
                    collect_entities(c, out);
                }
            }
            _ => {}
        }
    }
}

pub struct SpDescriptor<'a> {
    pub entity_id: &'a str,
    pub acs_url: &'a str,
    /// Our SingleLogoutService (same URL for both bindings).
    pub slo_url: &'a str,
    pub cert_der: Option<&'a [u8]>,
    pub sign_requests: bool,
}

pub fn render_sp(sp: &SpDescriptor) -> String {
    let mut keys = String::new();
    if let Some(der) = sp.cert_der {
        let b64 = STANDARD.encode(der);
        for use_ in ["signing", "encryption"] {
            keys.push_str(&format!(
                r#"<md:KeyDescriptor use="{use_}"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
            ));
        }
    }
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">"#,
            r#"<md:SPSSODescriptor AuthnRequestsSigned="{signed}" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            "{keys}",
            r#"<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"#,
            r#"<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"#,
            r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{slo}"/>"#,
            r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{slo}"/>"#,
            r#"<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"/>"#,
            r#"</md:SPSSODescriptor>"#,
            r#"</md:EntityDescriptor>"#
        ),
        entity = xml_attr(sp.entity_id),
        signed = sp.sign_requests,
        keys = keys,
        acs = xml_attr(sp.acs_url),
        slo = xml_attr(sp.slo_url),
    )
}

pub fn xml_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aggregate_and_picks_entity() {
        let key = crate::saml::test_support::idp_key();
        let cert = STANDARD.encode(crate::saml::test_support::idp_cert_der());
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <md:EntityDescriptor entityID="https://sp.example/other"><md:SPSSODescriptor/></md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://idp.example/saml">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
        {cert}
      </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
      <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example/sso/post"/>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso/redirect"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>"#
        );
        let md = parse_idp(&xml, None).unwrap();
        assert_eq!(md.entity_id, "https://idp.example/saml");
        assert_eq!(
            md.sso_redirect.as_deref(),
            Some("https://idp.example/sso/redirect")
        );
        assert_eq!(md.sso_post.as_deref(), Some("https://idp.example/sso/post"));
        assert!(md.want_authn_requests_signed);
        assert_eq!(md.signing_keys.len(), 1);
        assert_eq!(&md.signing_keys[0], key.public_key());
        assert!(parse_idp(&xml, Some("https://sp.example/other")).is_err());
    }

    #[test]
    fn sp_metadata_is_well_formed() {
        let out = render_sp(&SpDescriptor {
            entity_id: "https://t.example/api/v1/auth/sso/corp/saml/metadata",
            acs_url: "https://t.example/api/v1/auth/sso/saml/acs?x=1&y=2",
            slo_url: "https://t.example/api/v1/auth/sso/saml/slo",
            cert_der: Some(b"\x30\x00"),
            sign_requests: true,
        });
        let doc = Document::parse(&out).unwrap();
        assert_eq!(doc.root_element().tag_name().name(), "EntityDescriptor");
        assert!(out.contains("&amp;y=2"));
        assert_eq!(out.matches("<md:KeyDescriptor").count(), 2);
    }
}
