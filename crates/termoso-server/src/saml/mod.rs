//! SAML 2.0 Service Provider: SP-initiated Web Browser SSO with the
//! HTTP-Redirect (or HTTP-POST) binding for the `AuthnRequest` and HTTP-POST
//! for the `Response`. Pure Rust — no libxml2/xmlsec at runtime.
//!
//! Security model, in order of checks on the ACS:
//! `InResponseTo` must match the request we issued for this flow (no
//! IdP-initiated/unsolicited responses), `Destination` must be our ACS,
//! the `Issuer` must be the IdP from metadata, the status must be `Success`,
//! the response or the (possibly encrypted) assertion must carry a valid
//! XML-DSig from a metadata signing key, and the assertion's `Conditions`
//! (time window, `Audience`) and bearer `SubjectConfirmation` (`Recipient`,
//! `NotOnOrAfter`, `InResponseTo`) must all hold. SAML only proves who the
//! user is; the OPAQUE password still gates the vault.

pub mod c14n;
pub mod dsig;
pub mod metadata;
pub mod sp_key;
pub mod xmlenc;

use std::io::Read as _;
use std::io::Write as _;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Duration, Utc};
use roxmltree::{Document, Node};
pub use sp_key::SpKey;

pub const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const NAMEID_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Attribute names that commonly carry the user's email, in preference order.
const EMAIL_ATTRS: &[&str] = &[
    "email",
    "mail",
    "emailAddress",
    "emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "http://schemas.xmlsoap.org/claims/EmailAddress",
];
const NAME_ATTRS: &[&str] = &[
    "displayName",
    "displayname",
    "name",
    "cn",
    "urn:oid:2.16.840.1.113730.3.1.241",
    "urn:oid:2.5.4.3",
    "http://schemas.microsoft.com/identity/claims/displayname",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
];
const GIVEN_NAME_ATTRS: &[&str] = &[
    "givenName",
    "firstName",
    "urn:oid:2.5.4.42",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
];
const SURNAME_ATTRS: &[&str] = &[
    "sn",
    "surname",
    "lastName",
    "urn:oid:2.5.4.4",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
];

#[derive(Debug, thiserror::Error)]
pub enum SamlError {
    #[error("malformed SAML response: {0}")]
    Malformed(String),
    #[error("SAML response was not issued for this login attempt")]
    InResponseTo,
    #[error("SAML response Destination does not match this server")]
    Destination,
    #[error("SAML response issuer does not match the IdP metadata")]
    Issuer,
    #[error("identity provider reported failure: {0}")]
    Status(String),
    #[error("SAML response is not signed")]
    Unsigned,
    #[error("SAML signature invalid: {0}")]
    Signature(#[from] dsig::DsigError),
    #[error("encrypted assertion: {0}")]
    Encrypted(#[from] xmlenc::EncError),
    #[error("encrypted assertion but this SP has no private key configured")]
    NoDecryptionKey,
    #[error("SAML assertion is not valid at this time")]
    Expired,
    #[error("SAML assertion audience does not include this SP")]
    Audience,
    #[error("SAML assertion recipient does not match this server")]
    Recipient,
    #[error("SAML assertion carries no usable email address")]
    NoEmail,
}

/// What the IdP asserted about the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlIdentity {
    /// Stable identifier for account linking: persistent `NameID` when the IdP
    /// gives one, otherwise the email.
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
    pub session_index: Option<String>,
    /// Group memberships (`memberOf`, `groups`, the Microsoft/xmlsoap claim URIs).
    pub groups: Vec<String>,
}

/// Attribute names that carry group membership.
const GROUP_ATTRIBUTES: &[&str] = &[
    "memberOf",
    "groups",
    "http://schemas.xmlsoap.org/claims/Group",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
];

pub struct SpConfig {
    pub entity_id: String,
    pub acs_url: String,
    /// Our SingleLogoutService endpoint (Redirect and POST bindings).
    pub slo_url: String,
    pub key: Option<SpKey>,
    pub cert_der: Option<Vec<u8>>,
    pub sign_requests: bool,
    pub allow_sha1: bool,
    pub email_attribute: Option<String>,
    pub name_attribute: Option<String>,
    pub clock_skew: Duration,
}

pub struct ServiceProvider {
    pub sp: SpConfig,
    pub idp: metadata::IdpMetadata,
}

/// Where to send the browser for a new login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthnRedirect {
    /// HTTP-Redirect binding: a GET URL.
    Url(String),
    /// HTTP-POST binding: form target + fields the browser must POST.
    Post {
        action: String,
        saml_request: String,
        relay_state: String,
    },
}

impl ServiceProvider {
    pub fn new(sp: SpConfig, idp: metadata::IdpMetadata) -> anyhow::Result<Self> {
        if sp.sign_requests && sp.key.is_none() {
            anyhow::bail!("signed AuthnRequests need an SP private key");
        }
        Ok(Self { sp, idp })
    }

    pub fn metadata_xml(&self) -> String {
        metadata::render_sp(&metadata::SpDescriptor {
            entity_id: &self.sp.entity_id,
            acs_url: &self.sp.acs_url,
            slo_url: &self.sp.slo_url,
            cert_der: self.sp.cert_der.as_deref(),
            sign_requests: self.sp.sign_requests,
        })
    }

    /// Fresh SAML message ID (NCName: must start with a letter or `_`).
    pub fn new_request_id() -> String {
        let mut b = [0u8; 20];
        rand::fill(&mut b);
        format!("_{}", hex::encode(b))
    }

    pub fn authn_request_xml(&self, request_id: &str, issued_at: DateTime<Utc>) -> String {
        let destination = self
            .idp
            .sso_redirect
            .as_deref()
            .or(self.idp.sso_post.as_deref())
            .unwrap_or_default();
        format!(
            concat!(
                r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
                r#"ID="{id}" Version="2.0" IssueInstant="{instant}" Destination="{dest}" "#,
                r#"ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs}">"#,
                r#"<saml:Issuer>{issuer}</saml:Issuer>"#,
                r#"<samlp:NameIDPolicy AllowCreate="true"/>"#,
                r#"</samlp:AuthnRequest>"#
            ),
            id = request_id,
            instant = issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            dest = metadata::xml_attr(destination),
            acs = metadata::xml_attr(&self.sp.acs_url),
            issuer = xml_text(&self.sp.entity_id),
        )
    }

    /// Build the AuthnRequest for `request_id` and the binding-specific
    /// redirect. `relay_state` is our opaque flow id.
    pub fn start(
        &self,
        request_id: &str,
        relay_state: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuthnRedirect> {
        let xml = self.authn_request_xml(request_id, now);
        if let Some(sso) = &self.idp.sso_redirect {
            // DEFLATE (raw) + base64 + URL-encode, signature over the encoded query.
            let mut enc =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(xml.as_bytes())?;
            let deflated = enc.finish()?;
            let mut query = format!(
                "SAMLRequest={}&RelayState={}",
                urlenc(&STANDARD.encode(deflated)),
                urlenc(relay_state)
            );
            if self.sp.sign_requests {
                let key = self
                    .sp
                    .key
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("no SP key"))?;
                query.push_str(&format!("&SigAlg={}", urlenc(dsig::RSA_SHA256)));
                let sig = key
                    .sign_sha256(query.as_bytes())
                    .map_err(|_| anyhow::anyhow!("signing AuthnRequest"))?;
                query.push_str(&format!("&Signature={}", urlenc(&STANDARD.encode(sig))));
            }
            let sep = if sso.contains('?') { '&' } else { '?' };
            return Ok(AuthnRedirect::Url(format!("{sso}{sep}{query}")));
        }
        let action = self
            .idp
            .sso_post
            .clone()
            .ok_or_else(|| anyhow::anyhow!("IdP has no SSO endpoint"))?;
        let xml = if self.sp.sign_requests {
            let key = self
                .sp
                .key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no SP key"))?;
            dsig::sign_enveloped(&xml, request_id, key, self.sp.cert_der.as_deref())?
        } else {
            xml
        };
        Ok(AuthnRedirect::Post {
            action,
            saml_request: STANDARD.encode(xml),
            relay_state: relay_state.to_string(),
        })
    }

    /// Validate a base64 `SAMLResponse` posted to the ACS for the flow that
    /// issued `request_id`.
    pub fn consume_response(
        &self,
        saml_response_b64: &str,
        request_id: &str,
        now: DateTime<Utc>,
    ) -> Result<SamlIdentity, SamlError> {
        let compact: String = saml_response_b64
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if compact.len() > MAX_RESPONSE_BYTES {
            return Err(SamlError::Malformed("response too large".into()));
        }
        let bytes = STANDARD
            .decode(&compact)
            .map_err(|_| SamlError::Malformed("SAMLResponse is not base64".into()))?;
        let xml = String::from_utf8(bytes).map_err(|_| SamlError::Malformed("not UTF-8".into()))?;
        let doc = Document::parse(&xml).map_err(|e| SamlError::Malformed(e.to_string()))?;
        let response = doc.root_element();
        if !is(response, NS_PROTOCOL, "Response") {
            return Err(SamlError::Malformed("root is not samlp:Response".into()));
        }
        if response.attribute("Version") != Some("2.0") {
            return Err(SamlError::Malformed("unsupported SAML version".into()));
        }
        if response.attribute("InResponseTo") != Some(request_id) {
            return Err(SamlError::InResponseTo);
        }
        if let Some(dest) = response.attribute("Destination")
            && dest != self.sp.acs_url
        {
            return Err(SamlError::Destination);
        }
        if let Some(issuer) = child(response, NS_ASSERTION, "Issuer")
            && issuer.text().map(str::trim) != Some(self.idp.entity_id.as_str())
        {
            return Err(SamlError::Issuer);
        }
        let response_signed = if dsig::is_signed(response) {
            dsig::verify_enveloped(&doc, response, &self.idp.signing_keys, self.sp.allow_sha1)?;
            true
        } else {
            false
        };
        self.check_status(response, response_signed)?;

        // Exactly one assertion, plain or encrypted.
        let plain: Vec<Node> = children(response, NS_ASSERTION, "Assertion").collect();
        let encrypted: Vec<Node> = children(response, NS_ASSERTION, "EncryptedAssertion").collect();
        match (plain.len(), encrypted.len()) {
            (1, 0) => self.consume_assertion(&doc, plain[0], response_signed, request_id, now),
            (0, 1) => {
                let key = self.sp.key.as_ref().ok_or(SamlError::NoDecryptionKey)?;
                let wrapped = xmlenc::decrypt_assertion(encrypted[0], key, self.sp.allow_sha1)?;
                let adoc =
                    Document::parse(&wrapped).map_err(|e| SamlError::Malformed(e.to_string()))?;
                let assertion = adoc
                    .root_element()
                    .children()
                    .find(|c| c.is_element())
                    .filter(|a| is(*a, NS_ASSERTION, "Assertion"))
                    .ok_or_else(|| {
                        SamlError::Malformed("decrypted content is not an Assertion".into())
                    })?;
                self.consume_assertion(&adoc, assertion, response_signed, request_id, now)
            }
            (0, 0) => Err(SamlError::Malformed("response has no assertion".into())),
            _ => Err(SamlError::Malformed(
                "response has more than one assertion".into(),
            )),
        }
    }

    /// Free-text `StatusMessage` is only surfaced from a signed response:
    /// anyone can POST an unsigned failure to the ACS.
    fn check_status(&self, response: Node, signed: bool) -> Result<(), SamlError> {
        let status = child(response, NS_PROTOCOL, "Status")
            .ok_or_else(|| SamlError::Malformed("no Status".into()))?;
        let code = child(status, NS_PROTOCOL, "StatusCode")
            .ok_or_else(|| SamlError::Malformed("no StatusCode".into()))?;
        if code.attribute("Value") == Some(STATUS_SUCCESS) {
            return Ok(());
        }
        let mut detail = code
            .attribute("Value")
            .unwrap_or("unknown")
            .rsplit(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        if let Some(sub) = child(code, NS_PROTOCOL, "StatusCode").and_then(|c| c.attribute("Value"))
        {
            detail.push_str(" / ");
            detail.push_str(sub.rsplit(':').next().unwrap_or(sub));
        }
        if let Some(msg) = child(status, NS_PROTOCOL, "StatusMessage")
            .filter(|_| signed)
            .and_then(|m| m.text())
        {
            let msg: String = msg.trim().chars().take(200).collect();
            if !msg.is_empty() {
                detail.push_str(": ");
                detail.push_str(&msg);
            }
        }
        Err(SamlError::Status(detail))
    }

    fn consume_assertion(
        &self,
        doc: &Document,
        assertion: Node,
        response_signed: bool,
        request_id: &str,
        now: DateTime<Utc>,
    ) -> Result<SamlIdentity, SamlError> {
        if dsig::is_signed(assertion) {
            dsig::verify_enveloped(doc, assertion, &self.idp.signing_keys, self.sp.allow_sha1)?;
        } else if !response_signed {
            return Err(SamlError::Unsigned);
        }
        if assertion.attribute("Version") != Some("2.0") {
            return Err(SamlError::Malformed("unsupported assertion version".into()));
        }
        let issuer = child(assertion, NS_ASSERTION, "Issuer")
            .and_then(|i| i.text())
            .map(str::trim)
            .ok_or_else(|| SamlError::Malformed("assertion without Issuer".into()))?;
        if issuer != self.idp.entity_id {
            return Err(SamlError::Issuer);
        }

        let skew = self.sp.clock_skew;
        let conditions = child(assertion, NS_ASSERTION, "Conditions")
            .ok_or_else(|| SamlError::Malformed("assertion without Conditions".into()))?;
        if let Some(nb) = conditions.attribute("NotBefore")
            && parse_time(nb)? > now + skew
        {
            return Err(SamlError::Expired);
        }
        if let Some(na) = conditions.attribute("NotOnOrAfter")
            && parse_time(na)? <= now - skew
        {
            return Err(SamlError::Expired);
        }
        let mut audience_ok = false;
        let mut any_audience = false;
        for ar in children(conditions, NS_ASSERTION, "AudienceRestriction") {
            for a in children(ar, NS_ASSERTION, "Audience") {
                any_audience = true;
                if a.text().map(str::trim) == Some(self.sp.entity_id.as_str()) {
                    audience_ok = true;
                }
            }
        }
        if !any_audience || !audience_ok {
            return Err(SamlError::Audience);
        }

        let subject = child(assertion, NS_ASSERTION, "Subject")
            .ok_or_else(|| SamlError::Malformed("assertion without Subject".into()))?;
        let mut bearer_ok = false;
        let mut bearer_err: Option<SamlError> = None;
        for sc in children(subject, NS_ASSERTION, "SubjectConfirmation") {
            if sc.attribute("Method") != Some(CM_BEARER) {
                continue;
            }
            let data = child(sc, NS_ASSERTION, "SubjectConfirmationData");
            let res = (|| -> Result<(), SamlError> {
                if let Some(d) = data {
                    if let Some(r) = d.attribute("Recipient")
                        && r != self.sp.acs_url
                    {
                        return Err(SamlError::Recipient);
                    }
                    if let Some(na) = d.attribute("NotOnOrAfter")
                        && parse_time(na)? <= now - skew
                    {
                        return Err(SamlError::Expired);
                    }
                    if let Some(nb) = d.attribute("NotBefore")
                        && parse_time(nb)? > now + skew
                    {
                        return Err(SamlError::Expired);
                    }
                    if let Some(irt) = d.attribute("InResponseTo")
                        && irt != request_id
                    {
                        return Err(SamlError::InResponseTo);
                    }
                }
                Ok(())
            })();
            match res {
                Ok(()) => bearer_ok = true,
                Err(e) => bearer_err = Some(e),
            }
        }
        if !bearer_ok {
            return Err(bearer_err
                .unwrap_or_else(|| SamlError::Malformed("no bearer SubjectConfirmation".into())));
        }

        // Identity.
        let name_id = child(subject, NS_ASSERTION, "NameID");
        let name_id_value = name_id
            .and_then(|n| n.text())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let name_id_format = name_id.and_then(|n| n.attribute("Format"));
        let attrs: Vec<(String, Vec<String>)> =
            children(assertion, NS_ASSERTION, "AttributeStatement")
                .flat_map(|st| children(st, NS_ASSERTION, "Attribute"))
                .map(|a| {
                    let values = children(a, NS_ASSERTION, "AttributeValue")
                        .filter_map(|v| v.text())
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                        .collect();
                    (a.attribute("Name").unwrap_or("").to_string(), values)
                })
                .collect();
        let lookup = |names: &[&str]| -> Option<String> {
            names.iter().find_map(|n| {
                attrs
                    .iter()
                    .find(|(name, values)| name.eq_ignore_ascii_case(n) && !values.is_empty())
                    .map(|(_, v)| v[0].clone())
            })
        };

        let email = match &self.sp.email_attribute {
            Some(attr) => lookup(&[attr.as_str()]),
            None => lookup(EMAIL_ATTRS).or_else(|| {
                name_id_value
                    .filter(|v| name_id_format == Some(metadata::NAMEID_EMAIL) || v.contains('@'))
                    .map(String::from)
            }),
        }
        .ok_or(SamlError::NoEmail)?;

        let name = match &self.sp.name_attribute {
            Some(attr) => lookup(&[attr.as_str()]),
            None => lookup(NAME_ATTRS).or_else(|| {
                let given = lookup(GIVEN_NAME_ATTRS);
                let sur = lookup(SURNAME_ATTRS);
                match (given, sur) {
                    (Some(g), Some(s)) => Some(format!("{g} {s}")),
                    (Some(g), None) => Some(g),
                    (None, Some(s)) => Some(s),
                    (None, None) => None,
                }
            }),
        };

        let subject_id = match (name_id_value, name_id_format) {
            (Some(v), Some(NAMEID_TRANSIENT)) if !v.is_empty() => email.clone(),
            (Some(v), _) => v.to_string(),
            (None, _) => email.clone(),
        };
        let session_index = children(assertion, NS_ASSERTION, "AuthnStatement")
            .find_map(|s| s.attribute("SessionIndex"))
            .map(String::from);
        let groups: Vec<String> = attrs
            .iter()
            .filter(|(n, _)| GROUP_ATTRIBUTES.iter().any(|g| g.eq_ignore_ascii_case(n)))
            .flat_map(|(_, v)| v.iter().cloned())
            .collect();
        Ok(SamlIdentity {
            subject: subject_id,
            email,
            name,
            session_index,
            groups,
        })
    }
}

/// A `LogoutRequest` from the IdP: IdP-initiated Single Logout, or the IdP
/// propagating a logout another service provider started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutRequest {
    pub id: String,
    pub name_id: String,
    /// IdP sessions to end; empty means every session of the subject.
    pub session_indexes: Vec<String>,
}

/// One message at our SingleLogoutService endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SloMessage {
    Request(LogoutRequest),
    /// The IdP answering a `LogoutRequest` we sent.
    Response {
        in_response_to: Option<String>,
        success: bool,
    },
}

/// Percent-decode one query value (the Redirect binding form-encodes them).
fn urldec(s: &str) -> String {
    url::form_urlencoded::parse(format!("v={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

impl ServiceProvider {
    /// Whether the IdP advertises a SingleLogoutService at all.
    pub fn slo_enabled(&self) -> bool {
        self.idp.slo_redirect.is_some() || self.idp.slo_post.is_some()
    }

    /// HTTP-Redirect binding at our SLO endpoint. `raw_query` is the query
    /// string exactly as received: the IdP's signature covers the encoded
    /// `SAMLRequest`/`SAMLResponse`, `RelayState` and `SigAlg` values as
    /// sent. Unsigned messages are rejected — anyone could otherwise sign a
    /// user out by guessing their NameID. Returns the message and the
    /// decoded `RelayState`.
    pub fn consume_slo_redirect(
        &self,
        raw_query: &str,
        now: DateTime<Utc>,
    ) -> Result<(SloMessage, Option<String>), SamlError> {
        let (mut message, mut relay, mut sig_alg, mut signature) = (None, None, None, None);
        for part in raw_query.split('&') {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            match k {
                "SAMLRequest" | "SAMLResponse" if message.is_none() => message = Some((k, v)),
                "RelayState" => relay = Some(v),
                "SigAlg" => sig_alg = Some(v),
                "Signature" => signature = Some(v),
                _ => {}
            }
        }
        let (kind, raw) =
            message.ok_or_else(|| SamlError::Malformed("no SAMLRequest or SAMLResponse".into()))?;
        let (Some(alg), Some(sig)) = (sig_alg, signature) else {
            return Err(SamlError::Unsigned);
        };
        let mut signed = format!("{kind}={raw}");
        if let Some(r) = relay {
            signed.push_str(&format!("&RelayState={r}"));
        }
        signed.push_str(&format!("&SigAlg={alg}"));
        let sig_bytes = STANDARD
            .decode(urldec(sig).replace(char::is_whitespace, ""))
            .map_err(|_| SamlError::Malformed("Signature is not base64".into()))?;
        dsig::verify_detached(
            &urldec(alg),
            &self.idp.signing_keys,
            signed.as_bytes(),
            &sig_bytes,
            self.sp.allow_sha1,
        )?;
        let deflated = STANDARD
            .decode(urldec(raw).replace(char::is_whitespace, ""))
            .map_err(|_| SamlError::Malformed(format!("{kind} is not base64")))?;
        let mut xml = String::new();
        std::io::Read::take(
            flate2::read::DeflateDecoder::new(&deflated[..]),
            MAX_RESPONSE_BYTES as u64,
        )
        .read_to_string(&mut xml)
        .map_err(|_| SamlError::Malformed(format!("{kind} is not deflated XML")))?;
        let doc = Document::parse(&xml).map_err(|e| SamlError::Malformed(e.to_string()))?;
        let msg = self.parse_slo(&doc, now, false)?;
        Ok((msg, relay.map(urldec)))
    }

    /// HTTP-POST binding at our SLO endpoint: the message carries an
    /// enveloped signature, which must verify with an IdP key.
    pub fn consume_slo_post(
        &self,
        message_b64: &str,
        now: DateTime<Utc>,
    ) -> Result<SloMessage, SamlError> {
        let compact: String = message_b64.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.len() > MAX_RESPONSE_BYTES {
            return Err(SamlError::Malformed("message too large".into()));
        }
        let bytes = STANDARD
            .decode(&compact)
            .map_err(|_| SamlError::Malformed("message is not base64".into()))?;
        let xml = String::from_utf8(bytes).map_err(|_| SamlError::Malformed("not UTF-8".into()))?;
        let doc = Document::parse(&xml).map_err(|e| SamlError::Malformed(e.to_string()))?;
        self.parse_slo(&doc, now, true)
    }

    fn parse_slo(
        &self,
        doc: &Document,
        now: DateTime<Utc>,
        require_enveloped: bool,
    ) -> Result<SloMessage, SamlError> {
        let root = doc.root_element();
        let is_request = is(root, NS_PROTOCOL, "LogoutRequest");
        if !is_request && !is(root, NS_PROTOCOL, "LogoutResponse") {
            return Err(SamlError::Malformed(
                "root is not a LogoutRequest or LogoutResponse".into(),
            ));
        }
        if root.attribute("Version") != Some("2.0") {
            return Err(SamlError::Malformed("unsupported SAML version".into()));
        }
        if let Some(dest) = root.attribute("Destination")
            && dest != self.sp.slo_url
        {
            return Err(SamlError::Destination);
        }
        let issuer = child(root, NS_ASSERTION, "Issuer")
            .and_then(|i| i.text())
            .map(str::trim);
        if issuer != Some(self.idp.entity_id.as_str()) {
            return Err(SamlError::Issuer);
        }
        if require_enveloped {
            if !dsig::is_signed(root) {
                return Err(SamlError::Unsigned);
            }
            dsig::verify_enveloped(doc, root, &self.idp.signing_keys, self.sp.allow_sha1)?;
        }
        let skew = self.sp.clock_skew;
        if let Some(t) = root.attribute("IssueInstant")
            && parse_time(t)? > now + skew
        {
            return Err(SamlError::Expired);
        }
        if is_request {
            if let Some(t) = root.attribute("NotOnOrAfter")
                && parse_time(t)? + skew <= now
            {
                return Err(SamlError::Expired);
            }
            let id = root
                .attribute("ID")
                .ok_or_else(|| SamlError::Malformed("LogoutRequest without ID".into()))?
                .to_string();
            // EncryptedID is not supported; it shows up here as "no NameID".
            let name_id = child(root, NS_ASSERTION, "NameID")
                .and_then(|n| n.text())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| SamlError::Malformed("LogoutRequest without NameID".into()))?
                .to_string();
            let session_indexes = children(root, NS_PROTOCOL, "SessionIndex")
                .filter_map(|n| n.text())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            Ok(SloMessage::Request(LogoutRequest {
                id,
                name_id,
                session_indexes,
            }))
        } else {
            let success = child(root, NS_PROTOCOL, "Status")
                .and_then(|s| child(s, NS_PROTOCOL, "StatusCode"))
                .and_then(|c| c.attribute("Value"))
                == Some(STATUS_SUCCESS);
            Ok(SloMessage::Response {
                in_response_to: root.attribute("InResponseTo").map(String::from),
                success,
            })
        }
    }

    /// Redirect-binding message to `endpoint`: DEFLATE + base64 + URL-encode,
    /// signed over the encoded query when the SP signs requests.
    fn redirect_to(
        &self,
        endpoint: &str,
        param: &str,
        xml: &str,
        relay_state: Option<&str>,
    ) -> anyhow::Result<String> {
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(xml.as_bytes())?;
        let deflated = enc.finish()?;
        let mut query = format!("{param}={}", urlenc(&STANDARD.encode(deflated)));
        if let Some(r) = relay_state {
            query.push_str(&format!("&RelayState={}", urlenc(r)));
        }
        if self.sp.sign_requests {
            let key = self
                .sp
                .key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no SP key"))?;
            query.push_str(&format!("&SigAlg={}", urlenc(dsig::RSA_SHA256)));
            let sig = key
                .sign_sha256(query.as_bytes())
                .map_err(|_| anyhow::anyhow!("signing SLO message"))?;
            query.push_str(&format!("&Signature={}", urlenc(&STANDARD.encode(sig))));
        }
        let sep = if endpoint.contains('?') { '&' } else { '?' };
        Ok(format!("{endpoint}{sep}{query}"))
    }

    /// Answer the IdP's `LogoutRequest` with a successful `LogoutResponse`.
    /// `None` when the IdP has no Redirect-binding SLO endpoint to send it to.
    pub fn logout_response_url(
        &self,
        in_response_to: &str,
        relay_state: Option<&str>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<String>> {
        let Some(dest) = &self.idp.slo_redirect else {
            return Ok(None);
        };
        let xml = format!(
            concat!(
                r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
                r#"ID="{id}" Version="2.0" IssueInstant="{instant}" Destination="{dest}" InResponseTo="{irt}">"#,
                r#"<saml:Issuer>{issuer}</saml:Issuer>"#,
                r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
                r#"</samlp:LogoutResponse>"#
            ),
            id = Self::new_request_id(),
            instant = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            dest = metadata::xml_attr(dest),
            irt = metadata::xml_attr(in_response_to),
            issuer = xml_text(&self.sp.entity_id),
        );
        self.redirect_to(dest, "SAMLResponse", &xml, relay_state)
            .map(Some)
    }

    /// SP-initiated logout: ask the IdP to end the session it opened for
    /// `name_id` (narrowed to `session_index` when we know it). `None` when
    /// the IdP has no Redirect-binding SLO endpoint.
    pub fn logout_request_url(
        &self,
        request_id: &str,
        name_id: &str,
        session_index: Option<&str>,
        relay_state: Option<&str>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<String>> {
        let Some(dest) = &self.idp.slo_redirect else {
            return Ok(None);
        };
        let si = session_index
            .map(|s| format!("<samlp:SessionIndex>{}</samlp:SessionIndex>", xml_text(s)))
            .unwrap_or_default();
        let xml = format!(
            concat!(
                r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
                r#"ID="{id}" Version="2.0" IssueInstant="{instant}" Destination="{dest}" NotOnOrAfter="{noa}">"#,
                r#"<saml:Issuer>{issuer}</saml:Issuer><saml:NameID>{name_id}</saml:NameID>{si}"#,
                r#"</samlp:LogoutRequest>"#
            ),
            id = request_id,
            instant = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            dest = metadata::xml_attr(dest),
            noa = (now + chrono::Duration::minutes(5))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            issuer = xml_text(&self.sp.entity_id),
            name_id = xml_text(name_id),
            si = si,
        );
        self.redirect_to(dest, "SAMLRequest", &xml, relay_state)
            .map(Some)
    }
}

fn is(n: Node, ns: &str, name: &str) -> bool {
    n.is_element() && n.tag_name().namespace() == Some(ns) && n.tag_name().name() == name
}

fn child<'a, 'i>(n: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| is(*c, ns, name))
}

fn children<'a, 'i>(
    n: Node<'a, 'i>,
    ns: &'static str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'i>> {
    n.children().filter(move |c| is(*c, ns, name))
}

fn parse_time(s: &str) -> Result<DateTime<Utc>, SamlError> {
    DateTime::parse_from_rfc3339(s.trim())
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| SamlError::Malformed(format!("bad timestamp {s:?}")))
}

fn xml_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Percent-encode for the HTTP-Redirect binding (RFC 3986 unreserved kept).
fn urlenc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// Decode a PEM (or bare base64) certificate to DER.
pub fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    Ok(STANDARD.decode(body)?)
}

/// Parse a PEM RSA private key (PKCS#8 or PKCS#1) into the SP key.
pub fn parse_private_key(pem: &str) -> anyhow::Result<SpKey> {
    Ok(SpKey::from_pem(pem)?)
}

/// Test fixtures shared by unit and integration tests: a mock IdP that mints
/// signed (optionally encrypted) responses with the fixture certificates.
#[cfg(any(test, feature = "saml-test-support"))]
pub mod test_support {
    use super::*;

    pub const IDP_KEY_PEM: &str = include_str!("../../tests/fixtures/saml/idp.key");
    pub const IDP_CERT_PEM: &str = include_str!("../../tests/fixtures/saml/idp.crt");
    pub const SP_KEY_PEM: &str = include_str!("../../tests/fixtures/saml/sp.key");
    pub const SP_CERT_PEM: &str = include_str!("../../tests/fixtures/saml/sp.crt");

    pub fn idp_key() -> SpKey {
        parse_private_key(IDP_KEY_PEM).unwrap()
    }
    pub fn idp_cert_der() -> Vec<u8> {
        pem_to_der(IDP_CERT_PEM).unwrap()
    }
    pub fn sp_key() -> SpKey {
        parse_private_key(SP_KEY_PEM).unwrap()
    }
    pub fn sp_public_key() -> rsa::RsaPublicKey {
        sp_key().public_key().clone()
    }
    /// A fresh key unrelated to any fixture.
    pub fn random_key() -> SpKey {
        SpKey::from_rsa(&rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap()).unwrap()
    }
    pub fn sp_cert_der() -> Vec<u8> {
        pem_to_der(SP_CERT_PEM).unwrap()
    }

    /// IdP metadata XML for `entity_id` with SSO at `sso_url` (HTTP-Redirect).
    pub fn idp_metadata_xml(entity_id: &str, sso_url: &str) -> String {
        idp_metadata_xml_with(entity_id, sso_url, metadata::BINDING_REDIRECT, false)
    }

    pub fn idp_metadata_xml_with(
        entity_id: &str,
        sso_url: &str,
        binding: &str,
        want_signed: bool,
    ) -> String {
        format!(
            concat!(
                r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{entity}">"#,
                r#"<md:IDPSSODescriptor WantAuthnRequestsSigned="{want_signed}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
                r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#,
                r#"<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"#,
                r#"<md:SingleSignOnService Binding="{binding}" Location="{sso}"/>"#,
                r#"</md:IDPSSODescriptor></md:EntityDescriptor>"#
            ),
            entity = entity_id,
            want_signed = want_signed,
            cert = STANDARD.encode(idp_cert_der()),
            binding = binding,
            sso = sso_url
        )
    }

    /// IdP metadata with a Redirect-binding SingleLogoutService.
    pub fn idp_metadata_xml_slo(entity_id: &str, sso_url: &str, slo_url: &str) -> String {
        idp_metadata_xml(entity_id, sso_url).replace(
            "</md:IDPSSODescriptor>",
            &format!(
                r#"<md:SingleLogoutService Binding="{}" Location="{slo_url}"/></md:IDPSSODescriptor>"#,
                metadata::BINDING_REDIRECT
            ),
        )
    }

    /// Redirect-binding query (`SAMLRequest`/`SAMLResponse`, `RelayState`,
    /// `SigAlg`, `Signature`) signed with `key`.
    pub fn redirect_query(
        param: &str,
        xml: &str,
        relay_state: Option<&str>,
        key: &SpKey,
    ) -> String {
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(xml.as_bytes()).unwrap();
        let mut query = format!(
            "{param}={}",
            urlenc(&STANDARD.encode(enc.finish().unwrap()))
        );
        if let Some(r) = relay_state {
            query.push_str(&format!("&RelayState={}", urlenc(r)));
        }
        query.push_str(&format!("&SigAlg={}", urlenc(dsig::RSA_SHA256)));
        let sig = key.sign_sha256(query.as_bytes()).unwrap();
        query.push_str(&format!("&Signature={}", urlenc(&STANDARD.encode(sig))));
        query
    }

    /// A `LogoutRequest` the IdP would send to our SLO endpoint (Redirect
    /// binding, signed with the IdP key). Returns `(query, request id)`.
    pub fn logout_request_query(
        idp_entity_id: &str,
        destination: &str,
        name_id: &str,
        session_index: Option<&str>,
        relay_state: Option<&str>,
    ) -> (String, String) {
        let id = format!("_lr{}", hex::encode(rand::random::<[u8; 8]>()));
        let si = session_index
            .map(|s| format!("<samlp:SessionIndex>{s}</samlp:SessionIndex>"))
            .unwrap_or_default();
        let xml = format!(
            concat!(
                r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
                r#"ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{dest}">"#,
                r#"<saml:Issuer>{issuer}</saml:Issuer><saml:NameID>{name_id}</saml:NameID>{si}</samlp:LogoutRequest>"#
            ),
            id = id,
            now = ts(Utc::now()),
            dest = metadata::xml_attr(destination),
            issuer = idp_entity_id,
            name_id = name_id,
            si = si,
        );
        (
            redirect_query("SAMLRequest", &xml, relay_state, &idp_key()),
            id,
        )
    }

    /// The IdP's `LogoutResponse` to a request of ours.
    pub fn logout_response_query(
        idp_entity_id: &str,
        destination: &str,
        in_response_to: &str,
        relay_state: Option<&str>,
    ) -> String {
        let xml = format!(
            concat!(
                r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
                r#"ID="_lp{id}" Version="2.0" IssueInstant="{now}" Destination="{dest}" InResponseTo="{irt}">"#,
                r#"<saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{ok}"/></samlp:Status></samlp:LogoutResponse>"#
            ),
            id = hex::encode(rand::random::<[u8; 8]>()),
            now = ts(Utc::now()),
            dest = metadata::xml_attr(destination),
            irt = in_response_to,
            issuer = idp_entity_id,
            ok = STATUS_SUCCESS,
        );
        redirect_query("SAMLResponse", &xml, relay_state, &idp_key())
    }

    /// Everything a test needs to shape a response.
    #[derive(Clone)]
    pub struct ResponseSpec {
        pub idp_entity_id: String,
        pub sp_entity_id: String,
        pub acs_url: String,
        pub in_response_to: String,
        pub name_id: String,
        pub name_id_format: Option<String>,
        pub attributes: Vec<(String, String)>,
        pub now: DateTime<Utc>,
        pub not_before: Option<DateTime<Utc>>,
        pub not_on_or_after: Option<DateTime<Utc>>,
        pub audience: Option<String>,
        pub recipient: Option<String>,
        pub destination: Option<String>,
        pub status: String,
        pub status_message: Option<String>,
        pub sign_assertion: bool,
        pub sign_response: bool,
        pub encrypt_for: Option<rsa::RsaPublicKey>,
    }

    impl ResponseSpec {
        pub fn new(
            idp_entity_id: &str,
            sp_entity_id: &str,
            acs_url: &str,
            in_response_to: &str,
            email: &str,
        ) -> Self {
            let now = Utc::now();
            Self {
                idp_entity_id: idp_entity_id.into(),
                sp_entity_id: sp_entity_id.into(),
                acs_url: acs_url.into(),
                in_response_to: in_response_to.into(),
                name_id: email.into(),
                name_id_format: Some(metadata::NAMEID_EMAIL.into()),
                attributes: vec![],
                now,
                not_before: Some(now - Duration::minutes(1)),
                not_on_or_after: Some(now + Duration::minutes(5)),
                audience: Some(sp_entity_id.into()),
                recipient: Some(acs_url.into()),
                destination: Some(acs_url.into()),
                status: STATUS_SUCCESS.into(),
                status_message: None,
                sign_assertion: true,
                sign_response: false,
                encrypt_for: None,
            }
        }
    }

    fn ts(t: DateTime<Utc>) -> String {
        t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    /// Build the response XML (unencoded).
    pub fn build_response_xml(spec: &ResponseSpec) -> String {
        let key = idp_key();
        let cert = idp_cert_der();
        let rid = format!("_r{}", hex::encode(rand::random::<[u8; 8]>()));
        let aid = format!("_a{}", hex::encode(rand::random::<[u8; 8]>()));
        let mut conditions = String::from("<saml:Conditions");
        if let Some(nb) = spec.not_before {
            conditions.push_str(&format!(r#" NotBefore="{}""#, ts(nb)));
        }
        if let Some(na) = spec.not_on_or_after {
            conditions.push_str(&format!(r#" NotOnOrAfter="{}""#, ts(na)));
        }
        conditions.push('>');
        if let Some(aud) = &spec.audience {
            conditions.push_str(&format!(
                "<saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction>",
                xml_text(aud)
            ));
        }
        conditions.push_str("</saml:Conditions>");
        let mut scd = format!(
            r#"<saml:SubjectConfirmationData InResponseTo="{}""#,
            spec.in_response_to
        );
        if let Some(r) = &spec.recipient {
            scd.push_str(&format!(r#" Recipient="{}""#, metadata::xml_attr(r)));
        }
        if let Some(na) = spec.not_on_or_after {
            scd.push_str(&format!(r#" NotOnOrAfter="{}""#, ts(na)));
        }
        scd.push_str("/>");
        let fmt = spec
            .name_id_format
            .as_ref()
            .map(|f| format!(r#" Format="{f}""#))
            .unwrap_or_default();
        let attrs = if spec.attributes.is_empty() {
            String::new()
        } else {
            let mut s = String::from("<saml:AttributeStatement>");
            for (n, v) in &spec.attributes {
                s.push_str(&format!(
                    r#"<saml:Attribute Name="{}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">{}</saml:AttributeValue></saml:Attribute>"#,
                    metadata::xml_attr(n),
                    xml_text(v)
                ));
            }
            s.push_str("</saml:AttributeStatement>");
            s
        };
        let assertion = format!(
            concat!(
                r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="{aid}" Version="2.0" IssueInstant="{now}">"#,
                "<saml:Issuer>{idp}</saml:Issuer>",
                r#"<saml:Subject><saml:NameID{fmt}>{nameid}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">{scd}</saml:SubjectConfirmation></saml:Subject>"#,
                "{conditions}",
                r#"<saml:AuthnStatement AuthnInstant="{now}" SessionIndex="{aid}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#,
                "{attrs}",
                "</saml:Assertion>"
            ),
            aid = aid,
            now = ts(spec.now),
            idp = xml_text(&spec.idp_entity_id),
            fmt = fmt,
            nameid = xml_text(&spec.name_id),
            scd = scd,
            conditions = conditions,
            attrs = attrs,
        );
        let assertion = if spec.sign_assertion {
            dsig::sign_enveloped(&assertion, &aid, &key, Some(&cert)).unwrap()
        } else {
            assertion
        };
        let assertion = match &spec.encrypt_for {
            Some(pk) => xmlenc::encrypt_assertion(&assertion, pk),
            None => assertion,
        };
        let dest = spec
            .destination
            .as_ref()
            .map(|d| format!(r#" Destination="{}""#, metadata::xml_attr(d)))
            .unwrap_or_default();
        let response = format!(
            concat!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{rid}" Version="2.0" IssueInstant="{now}"{dest} InResponseTo="{irt}">"#,
                "<saml:Issuer>{idp}</saml:Issuer>",
                r#"<samlp:Status><samlp:StatusCode Value="{status}"/>{status_message}</samlp:Status>"#,
                "{assertion}",
                "</samlp:Response>"
            ),
            rid = rid,
            now = ts(spec.now),
            dest = dest,
            irt = spec.in_response_to,
            idp = xml_text(&spec.idp_entity_id),
            status = spec.status,
            status_message = spec
                .status_message
                .as_deref()
                .map(|m| format!("<samlp:StatusMessage>{}</samlp:StatusMessage>", xml_text(m)))
                .unwrap_or_default(),
            assertion = assertion,
        );
        if spec.sign_response {
            dsig::sign_enveloped(&response, &rid, &key, Some(&cert)).unwrap()
        } else {
            response
        }
    }

    pub fn build_response_b64(spec: &ResponseSpec) -> String {
        STANDARD.encode(build_response_xml(spec))
    }

    /// Extract `SAMLRequest` and `RelayState` from a redirect URL and inflate
    /// the AuthnRequest XML.
    pub fn decode_redirect(url: &str) -> (String, String) {
        let u = url::Url::parse(url).unwrap();
        let mut req = None;
        let mut relay = None;
        for (k, v) in u.query_pairs() {
            match &*k {
                "SAMLRequest" | "SAMLResponse" => req = Some(v.to_string()),
                "RelayState" => relay = Some(v.to_string()),
                _ => {}
            }
        }
        let deflated = STANDARD.decode(req.unwrap()).unwrap();
        let mut out = Vec::new();
        std::io::Read::read_to_end(
            &mut flate2::read::DeflateDecoder::new(&deflated[..]),
            &mut out,
        )
        .unwrap();
        (String::from_utf8(out).unwrap(), relay.unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    const IDP: &str = "https://idp.example/saml";
    const SP: &str = "https://sp.example/api/v1/auth/sso/corp/saml/metadata";
    const ACS: &str = "https://sp.example/api/v1/auth/sso/saml/acs";
    const SLO: &str = "https://sp.example/api/v1/auth/sso/saml/slo";

    fn provider(with_key: bool) -> ServiceProvider {
        let idp =
            metadata::parse_idp(&idp_metadata_xml(IDP, "https://idp.example/sso"), None).unwrap();
        ServiceProvider::new(
            SpConfig {
                entity_id: SP.into(),
                acs_url: ACS.into(),
                slo_url: SLO.into(),
                key: with_key.then(sp_key),
                cert_der: with_key.then(sp_cert_der),
                sign_requests: with_key,
                allow_sha1: false,
                email_attribute: None,
                name_attribute: None,
                clock_skew: Duration::minutes(2),
            },
            idp,
        )
        .unwrap()
    }

    fn spec() -> ResponseSpec {
        ResponseSpec::new(IDP, SP, ACS, "_req1", "ada@example.com")
    }

    #[test]
    fn authn_request_redirect_binding() {
        let p = provider(true);
        let AuthnRedirect::Url(url) = p.start("_req1", "flow-1", Utc::now()).unwrap() else {
            panic!("redirect")
        };
        assert!(url.starts_with("https://idp.example/sso?SAMLRequest="));
        assert!(url.contains("&SigAlg=") && url.contains("&Signature="));
        let (xml, relay) = decode_redirect(&url);
        assert_eq!(relay, "flow-1");
        let doc = Document::parse(&xml).unwrap();
        let r = doc.root_element();
        assert_eq!(r.attribute("ID"), Some("_req1"));
        assert_eq!(r.attribute("AssertionConsumerServiceURL"), Some(ACS));
        assert_eq!(r.attribute("Destination"), Some("https://idp.example/sso"));

        // Signature over the query is verifiable with the SP certificate.
        let q = url.split_once('?').unwrap().1;
        let (signed, sig) = q.split_once("&Signature=").unwrap();
        let sig = STANDARD.decode(percent_decode(sig)).unwrap();
        let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(sp_public_key());
        rsa::signature::Verifier::verify(
            &vk,
            signed.as_bytes(),
            &rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap(),
        )
        .unwrap();
    }

    fn percent_decode(s: &str) -> String {
        url::form_urlencoded::parse(format!("v={s}").as_bytes())
            .next()
            .unwrap()
            .1
            .into_owned()
    }

    #[test]
    fn valid_signed_assertion() {
        let p = provider(false);
        let mut s = spec();
        s.attributes = vec![
            ("givenName".into(), "Ada".into()),
            ("sn".into(), "Lovelace".into()),
        ];
        let id = p
            .consume_response(&build_response_b64(&s), "_req1", s.now)
            .unwrap();
        assert_eq!(id.email, "ada@example.com");
        assert_eq!(id.subject, "ada@example.com");
        assert_eq!(id.name.as_deref(), Some("Ada Lovelace"));
        assert!(id.session_index.is_some());
    }

    #[test]
    fn valid_signed_response_unsigned_assertion() {
        let p = provider(false);
        let mut s = spec();
        s.sign_assertion = false;
        s.sign_response = true;
        s.name_id = "urn:persistent:abc".into();
        s.name_id_format = Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into());
        s.attributes = vec![
            (
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".into(),
                "Ada@Example.com".into(),
            ),
            (
                "http://schemas.microsoft.com/identity/claims/displayname".into(),
                "Ada L.".into(),
            ),
        ];
        let id = p
            .consume_response(&build_response_b64(&s), "_req1", s.now)
            .unwrap();
        assert_eq!(id.email, "Ada@Example.com");
        assert_eq!(id.subject, "urn:persistent:abc");
        assert_eq!(id.name.as_deref(), Some("Ada L."));
    }

    #[test]
    fn encrypted_assertion() {
        let p = provider(true);
        let mut s = spec();
        s.encrypt_for = Some(sp_public_key());
        let id = p
            .consume_response(&build_response_b64(&s), "_req1", s.now)
            .unwrap();
        assert_eq!(id.email, "ada@example.com");
        // Same response, SP without a key.
        assert!(matches!(
            provider(false).consume_response(&build_response_b64(&s), "_req1", s.now),
            Err(SamlError::NoDecryptionKey)
        ));
        // Encrypted, but signed by the response only (assertion unsigned).
        s.sign_assertion = false;
        s.sign_response = true;
        p.consume_response(&build_response_b64(&s), "_req1", s.now)
            .unwrap();
    }

    #[test]
    fn rejections() {
        let p = provider(false);
        let s = spec();
        let ok = build_response_b64(&s);
        // Wrong request id (unsolicited / replayed into another flow).
        assert!(matches!(
            p.consume_response(&ok, "_other", s.now),
            Err(SamlError::InResponseTo)
        ));
        // Expired / not yet valid.
        assert!(matches!(
            p.consume_response(&ok, "_req1", s.now + Duration::minutes(10)),
            Err(SamlError::Expired)
        ));
        assert!(matches!(
            p.consume_response(&ok, "_req1", s.now - Duration::minutes(10)),
            Err(SamlError::Expired)
        ));
        // Within skew is fine.
        p.consume_response(&ok, "_req1", s.now + Duration::minutes(6))
            .unwrap();

        let mut bad = s.clone();
        bad.sign_assertion = false;
        assert!(matches!(
            p.consume_response(&build_response_b64(&bad), "_req1", s.now),
            Err(SamlError::Unsigned)
        ));

        let mut bad = s.clone();
        bad.audience = Some("https://other.example".into());
        assert!(matches!(
            p.consume_response(&build_response_b64(&bad), "_req1", s.now),
            Err(SamlError::Audience)
        ));
        bad.audience = None;
        assert!(matches!(
            p.consume_response(&build_response_b64(&bad), "_req1", s.now),
            Err(SamlError::Audience)
        ));

        let mut bad = s.clone();
        bad.recipient = Some("https://evil.example/acs".into());
        assert!(matches!(
            p.consume_response(&build_response_b64(&bad), "_req1", s.now),
            Err(SamlError::Recipient)
        ));

        let mut bad = s.clone();
        bad.destination = Some("https://evil.example/acs".into());
        assert!(matches!(
            p.consume_response(&build_response_b64(&bad), "_req1", s.now),
            Err(SamlError::Destination)
        ));

        let mut bad = s.clone();
        bad.idp_entity_id = "https://evil.example/idp".into();
        assert!(matches!(
            p.consume_response(&build_response_b64(&bad), "_req1", s.now),
            Err(SamlError::Issuer)
        ));

        let mut bad = s.clone();
        bad.status = "urn:oasis:names:tc:SAML:2.0:status:Responder".into();
        assert!(matches!(
            p.consume_response(&build_response_b64(&bad), "_req1", s.now),
            Err(SamlError::Status(_))
        ));

        // Free-text StatusMessage reaches the user only from a signed response.
        bad.status_message = Some("call +1-555-SCAM to unlock".into());
        match p.consume_response(&build_response_b64(&bad), "_req1", s.now) {
            Err(SamlError::Status(d)) => assert_eq!(d, "Responder"),
            other => panic!("expected Status, got {other:?}"),
        }
        bad.sign_response = true;
        match p.consume_response(&build_response_b64(&bad), "_req1", s.now) {
            Err(SamlError::Status(d)) => assert_eq!(d, "Responder: call +1-555-SCAM to unlock"),
            other => panic!("expected Status, got {other:?}"),
        }

        let mut bad = s.clone();
        bad.name_id = "not-an-email".into();
        bad.name_id_format = None;
        assert!(matches!(
            p.consume_response(&build_response_b64(&bad), "_req1", s.now),
            Err(SamlError::NoEmail)
        ));

        // Tampered email inside a signed assertion.
        let xml = build_response_xml(&s).replace("ada@example.com", "eve@example.com");
        assert!(matches!(
            p.consume_response(&STANDARD.encode(xml), "_req1", s.now),
            Err(SamlError::Signature(dsig::DsigError::Digest))
        ));
        // Signed by an unknown key.
        let other = random_key();
        let mut unsigned = s.clone();
        unsigned.sign_assertion = false;
        let xml = build_response_xml(&unsigned);
        let rid = Document::parse(&xml)
            .unwrap()
            .root_element()
            .attribute("ID")
            .unwrap()
            .to_string();
        let forged = dsig::sign_enveloped(&xml, &rid, &other, None).unwrap();
        assert!(matches!(
            p.consume_response(&STANDARD.encode(forged), "_req1", s.now),
            Err(SamlError::Signature(dsig::DsigError::Signature))
        ));
        // Garbage.
        assert!(matches!(
            p.consume_response("%%%", "_req1", s.now),
            Err(SamlError::Malformed(_))
        ));
        assert!(matches!(
            p.consume_response(&STANDARD.encode("<a/>"), "_req1", s.now),
            Err(SamlError::Malformed(_))
        ));
    }

    #[test]
    fn configured_attributes_win() {
        let mut p = provider(false);
        p.sp.email_attribute = Some("corpMail".into());
        p.sp.name_attribute = Some("corpName".into());
        let mut s = spec();
        s.attributes = vec![
            ("corpMail".into(), "ada@corp.example".into()),
            ("corpName".into(), "A. L.".into()),
        ];
        let id = p
            .consume_response(&build_response_b64(&s), "_req1", s.now)
            .unwrap();
        assert_eq!(id.email, "ada@corp.example");
        assert_eq!(id.name.as_deref(), Some("A. L."));
        s.attributes.clear();
        assert!(matches!(
            p.consume_response(&build_response_b64(&s), "_req1", s.now),
            Err(SamlError::NoEmail)
        ));
    }

    #[test]
    fn sp_metadata() {
        let p = provider(true);
        let xml = p.metadata_xml();
        let doc = Document::parse(&xml).unwrap();
        assert_eq!(doc.root_element().attribute("entityID"), Some(SP));
        assert!(xml.contains(r#"AuthnRequestsSigned="true""#));
        assert!(xml.contains(&STANDARD.encode(sp_cert_der())));
    }
}

/// Responses signed by an independent XML-DSig implementation (python
/// `signxml`/libxml2) with the fixture IdP key: proves the canonicalizer and
/// verifier interoperate rather than merely round-trip with themselves.
#[cfg(test)]
mod interop_tests {
    use super::test_support::*;
    use super::*;

    const ASSERTION_EXC: &str = include_str!("../../tests/fixtures/saml/signxml-assertion-exc.xml");
    const RESPONSE_INC: &str = include_str!("../../tests/fixtures/saml/signxml-response-inc.xml");
    const RESPONSE_EXC_SHA512: &str =
        include_str!("../../tests/fixtures/saml/signxml-response-exc-sha512.xml");

    fn provider() -> ServiceProvider {
        let idp = metadata::parse_idp(
            &idp_metadata_xml("https://idp.example/saml", "https://idp.example/sso"),
            None,
        )
        .unwrap();
        ServiceProvider::new(
            SpConfig {
                entity_id: "https://sp.example/api/v1/auth/sso/corp/saml/metadata".into(),
                acs_url: "https://sp.example/api/v1/auth/sso/saml/acs".into(),
                slo_url: "https://sp.example/api/v1/auth/sso/saml/slo".into(),
                key: None,
                cert_der: None,
                sign_requests: false,
                allow_sha1: false,
                email_attribute: None,
                name_attribute: None,
                clock_skew: Duration::minutes(2),
            },
            idp,
        )
        .unwrap()
    }

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn signxml_fixtures_verify() {
        let p = provider();
        for xml in [ASSERTION_EXC, RESPONSE_INC, RESPONSE_EXC_SHA512] {
            let id = p
                .consume_response(&STANDARD.encode(xml), "_req42", at())
                .unwrap();
            assert_eq!(id.email, "grace@example.com");
            assert_eq!(id.subject, "user-42");
            assert_eq!(id.name.as_deref(), Some("Grace & Hopper <3"));
            assert_eq!(id.session_index.as_deref(), Some("_sess42"));
        }
    }

    #[test]
    fn signxml_fixtures_tampered_fail() {
        let p = provider();
        for xml in [ASSERTION_EXC, RESPONSE_INC, RESPONSE_EXC_SHA512] {
            let bad = xml.replace("grace@example.com", "mallory@example.com");
            assert!(matches!(
                p.consume_response(&STANDARD.encode(bad), "_req42", at()),
                Err(SamlError::Signature(dsig::DsigError::Digest))
            ));
        }
    }
}
