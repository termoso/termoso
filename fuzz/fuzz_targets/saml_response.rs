#![no_main]
//! The ACS entry point: base64 `SAMLResponse` → parsed, canonicalized,
//! digest/signature checked, optionally decrypted. A fixture SP/IdP pair is
//! used so a seed corpus of genuinely signed responses drives the fuzzer past
//! the early rejections.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use termoso_server::saml::test_support::{idp_metadata_xml, sp_cert_der, sp_key};
use termoso_server::saml::{ServiceProvider, SpConfig, metadata};

const IDP: &str = "https://idp.example/metadata";
const SP: &str = "https://sp.example/api/v1/auth/sso/corp/saml/metadata";
const ACS: &str = "https://sp.example/api/v1/auth/sso/saml/acs";

static PROVIDER: LazyLock<ServiceProvider> = LazyLock::new(|| {
    let idp = metadata::parse_idp(&idp_metadata_xml(IDP, "https://idp.example/sso"), None).unwrap();
    ServiceProvider::new(
        SpConfig {
            entity_id: SP.into(),
            acs_url: ACS.into(),
            slo_url: "https://sp.example/saml/slo".into(),
            key: Some(sp_key()),
            cert_der: Some(sp_cert_der()),
            sign_requests: true,
            allow_sha1: true,
            email_attribute: None,
            name_attribute: None,
            clock_skew: chrono::Duration::minutes(5),
        },
        idp,
    )
    .unwrap()
});

fuzz_target!(|data: &[u8]| {
    // Fuzz the decoded document: libFuzzer mutates bytes, we present them as
    // the base64 the browser would POST.
    let b64 = STANDARD.encode(data);
    let _ = PROVIDER.consume_response(&b64, "_req-fuzz", Utc::now());
});
