//! SAML 2.0 SP against an in-process mock IdP: the browser leg is simulated by
//! decoding the `AuthnRequest` we produce and POSTing a signed `Response`
//! minted with the fixture IdP key to the ACS.

mod common;

use common::*;
use reqwest::{Method, StatusCode, redirect::Policy};
use roxmltree::Document;
use termoso_proto::auth::{AuthResponse, SsoLogoutResponse, SsoResult, SsoStartResponse};
use termoso_server::saml::test_support::{self as saml_support, ResponseSpec};

const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

async fn start(s: &TestServer, provider: &str, redirect: Option<&str>) -> SsoStartResponse {
    let mut path = format!("/auth/sso/{provider}/start");
    if let Some(r) = redirect {
        let q: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("redirect", r)
            .finish();
        path = format!("{path}?{q}");
    }
    s.json(Method::GET, &path, None, NOBODY).await
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .pool_max_idle_per_host(0)
        .build()
        .unwrap()
}

/// POST a `SAMLResponse` to the ACS like the IdP-driven browser would.
async fn acs(s: &TestServer, relay_state: Option<&str>, saml_response: &str) -> reqwest::Response {
    let mut form = vec![("SAMLResponse", saml_response)];
    if let Some(r) = relay_state {
        form.push(("RelayState", r));
    }
    browser()
        .post(s.url("/auth/sso/saml/acs"))
        .header("x-forwarded-for", fake_ip())
        .form(&form)
        .send()
        .await
        .expect("acs")
}

async fn poll(s: &TestServer, flow_id: &str) -> SsoResult {
    s.json(
        Method::GET,
        &format!("/auth/sso/flow/{flow_id}"),
        None,
        NOBODY,
    )
    .await
}

/// What the IdP learns from our `AuthnRequest`.
struct Request {
    id: String,
    relay_state: String,
    acs_url: String,
    issuer: String,
}

fn parse_request(xml: &str, relay_state: String) -> Request {
    let doc = Document::parse(xml).unwrap();
    let root = doc.root_element();
    assert_eq!(root.tag_name().namespace(), Some(NS_PROTOCOL));
    assert_eq!(root.tag_name().name(), "AuthnRequest");
    assert_eq!(root.attribute("Version"), Some("2.0"));
    assert_eq!(root.attribute("Destination"), Some(SAML_IDP_SSO_URL));
    let issuer = root
        .children()
        .find(|c| c.tag_name().namespace() == Some(NS_ASSERTION) && c.tag_name().name() == "Issuer")
        .and_then(|i| i.text())
        .unwrap()
        .to_string();
    Request {
        id: root.attribute("ID").unwrap().to_string(),
        relay_state,
        acs_url: root
            .attribute("AssertionConsumerServiceURL")
            .unwrap()
            .to_string(),
        issuer,
    }
}

/// Follow the start URL the way a browser would and extract the request.
async fn browser_leg(s: &TestServer, flow: &SsoStartResponse) -> Request {
    if flow.authorization_url.starts_with(SAML_IDP_SSO_URL) {
        let (xml, relay) = saml_support::decode_redirect(&flow.authorization_url);
        return parse_request(&xml, relay);
    }
    // HTTP-POST binding: our server renders an auto-submitting form.
    assert!(
        flow.authorization_url
            .starts_with(&s.url("/auth/sso/saml/post/")),
        "{}",
        flow.authorization_url
    );
    let html = browser().get(&flow.authorization_url).send().await.unwrap();
    assert_eq!(html.status(), StatusCode::OK);
    let html = html.text().await.unwrap();
    let field = |name: &str| -> String {
        let marker = format!(r#"name="{name}" value=""#);
        let start = html.find(&marker).unwrap() + marker.len();
        let end = html[start..].find('"').unwrap();
        html[start..start + end]
            .replace("&amp;", "&")
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
    };
    assert!(html.contains(&format!(r#"action="{SAML_IDP_SSO_URL}""#)));
    let xml = String::from_utf8(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            field("SAMLRequest"),
        )
        .unwrap(),
    )
    .unwrap();
    parse_request(&xml, field("RelayState"))
}

fn spec_for(req: &Request, email: &str) -> ResponseSpec {
    ResponseSpec::new(SAML_IDP_ENTITY, &req.issuer, &req.acs_url, &req.id, email)
}

/// Start → IdP → ACS, returning the poll result.
async fn sign_in(
    s: &TestServer,
    provider: &str,
    shape: impl FnOnce(&Request) -> ResponseSpec,
) -> SsoResult {
    let flow = start(s, provider, None).await;
    let req = browser_leg(s, &flow).await;
    assert_eq!(req.relay_state, flow.flow_id);
    let resp = acs(
        s,
        Some(&req.relay_state),
        &saml_support::build_response_b64(&shape(&req)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    poll(s, &flow.flow_id).await
}

#[tokio::test]
async fn sp_metadata_is_served() {
    let Some(s) = server().await else { return };
    let resp = browser()
        .get(s.url(&format!("/auth/sso/{SAML_CORP_PROVIDER}/saml/metadata")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-type"],
        "application/samlmetadata+xml"
    );
    let xml = resp.text().await.unwrap();
    let doc = Document::parse(&xml).unwrap();
    assert_eq!(
        doc.root_element().attribute("entityID"),
        Some(
            s.url(&format!("/auth/sso/{SAML_CORP_PROVIDER}/saml/metadata"))
                .as_str()
        )
    );
    assert!(xml.contains(r#"AuthnRequestsSigned="true""#), "{xml}");
    assert!(xml.contains(&format!(r#"Location="{}""#, s.url("/auth/sso/saml/acs"))));

    // The redirect-binding provider has no key: unsigned requests, no cert.
    let xml = browser()
        .get(s.url(&format!("/auth/sso/{SAML_PROVIDER}/saml/metadata")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(xml.contains(r#"AuthnRequestsSigned="false""#));
    assert!(!xml.contains("X509Certificate"));

    // OIDC providers have none.
    s.expect_status(
        Method::GET,
        &format!("/auth/sso/{SSO_PROVIDER}/saml/metadata"),
        None,
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
}

#[tokio::test]
async fn saml_registers_then_logs_in() {
    let Some(s) = server().await else { return };
    let email = unique_email("saml");

    let flow = start(s, SAML_PROVIDER, None).await;
    let req = browser_leg(s, &flow).await;
    assert_eq!(req.acs_url, s.url("/auth/sso/saml/acs"));
    assert_eq!(
        req.issuer,
        s.url(&format!("/auth/sso/{SAML_PROVIDER}/saml/metadata"))
    );
    assert!(matches!(poll(s, &flow.flow_id).await, SsoResult::Pending));

    let mut spec = spec_for(&req, &email);
    spec.attributes = vec![("displayName".into(), "Ada Lovelace".into())];
    let resp = acs(
        s,
        Some(&flow.flow_id),
        &saml_support::build_response_b64(&spec),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let SsoResult::RegistrationRequired {
        sso_session,
        email: asserted,
        display_name,
    } = poll(s, &flow.flow_id).await
    else {
        panic!("expected registration_required")
    };
    assert_eq!(asserted, email);
    assert_eq!(display_name.as_deref(), Some("Ada Lovelace"));

    // The ACS is single-shot per flow: replaying the same response fails.
    let replay = acs(
        s,
        Some(&flow.flow_id),
        &saml_support::build_response_b64(&spec),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let password = "pw-saml-1234567890";
    let u = register_raw(s, &email, password, None, Some(sso_session)).await;
    assert!(u.session.user.email_verified);

    // Known account → login required; the password is still needed.
    let SsoResult::LoginRequired { sso_session, .. } =
        sign_in(s, SAML_PROVIDER, |r| spec_for(r, &email)).await
    else {
        panic!("expected login_required")
    };
    assert!(
        login_raw(
            s,
            &email,
            "wrong-password-12345",
            device("saml laptop"),
            Some(sso_session)
        )
        .await
        .is_err()
    );
    let SsoResult::LoginRequired { sso_session, .. } =
        sign_in(s, SAML_PROVIDER, |r| spec_for(r, &email)).await
    else {
        panic!("expected login_required")
    };
    let resp = login_raw(
        s,
        &email,
        password,
        device("saml laptop"),
        Some(sso_session),
    )
    .await
    .unwrap();
    let AuthResponse::Authenticated(sess) = resp else {
        panic!("expected a session, got {resp:?}")
    };
    assert_eq!(sess.user.id, u.id());

    // Identity linking by persistent NameID: the email at the IdP may change.
    let SsoResult::RegistrationRequired { .. } = sign_in(s, SAML_PROVIDER, |r| {
        let mut sp = spec_for(r, "fresh@example.com");
        sp.name_id = "urn:persistent:ada".into();
        sp.name_id_format = Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into());
        sp.attributes = vec![("mail".into(), "fresh@example.com".into())];
        sp
    })
    .await
    else {
        panic!("expected registration_required for a new persistent id")
    };
    let renamed = unique_email("renamed");
    let SsoResult::LoginRequired {
        email: asserted, ..
    } = sign_in(s, SAML_PROVIDER, |r| {
        let mut sp = spec_for(r, &renamed);
        sp.name_id = email.clone();
        sp.attributes = vec![("mail".into(), renamed.clone())];
        sp
    })
    .await
    else {
        panic!("expected login_required")
    };
    assert_eq!(
        asserted, email,
        "linked subject wins over the asserted email"
    );
}

#[tokio::test]
async fn post_binding_signed_requests_and_encrypted_assertions() {
    let Some(s) = server().await else { return };
    let email = unique_email("corp").replace("@test.local", &format!("@{SSO_CORP_DOMAIN}"));

    let flow = start(s, SAML_CORP_PROVIDER, None).await;
    let req = browser_leg(s, &flow).await;
    // The POST form carries a signed AuthnRequest (enveloped ds:Signature).
    let html = browser()
        .get(&flow.authorization_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let marker = r#"name="SAMLRequest" value=""#;
    let start_at = html.find(marker).unwrap() + marker.len();
    let end = html[start_at..].find('"').unwrap();
    let xml = String::from_utf8(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &html[start_at..start_at + end],
        )
        .unwrap(),
    )
    .unwrap();
    assert!(xml.contains("http://www.w3.org/2000/09/xmldsig#"), "{xml}");
    assert!(xml.contains("SignatureValue"));

    // Encrypted assertion for our SP certificate, email from the configured attribute.
    let mut spec = spec_for(&req, &email);
    spec.name_id = "opaque-id-1".into();
    spec.name_id_format = Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient".into());
    spec.attributes = vec![
        ("corpMail".into(), email.clone()),
        ("mail".into(), "ignored@other.test".into()),
    ];
    spec.encrypt_for = Some(saml_support::sp_public_key());
    let resp = acs(
        s,
        Some(&flow.flow_id),
        &saml_support::build_response_b64(&spec),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let SsoResult::RegistrationRequired {
        email: asserted, ..
    } = poll(s, &flow.flow_id).await
    else {
        panic!("expected registration_required")
    };
    assert_eq!(asserted, email);

    // Domain allow-list applies to the attribute value.
    let SsoResult::Failed { .. } = sign_in(s, SAML_CORP_PROVIDER, |r| {
        let mut sp = spec_for(r, "outsider@elsewhere.test");
        sp.attributes = vec![("corpMail".into(), "outsider@elsewhere.test".into())];
        sp
    })
    .await
    else {
        panic!("expected failure for a foreign domain")
    };
    // Without the configured attribute the email NameID is not used.
    let SsoResult::Failed { .. } = sign_in(s, SAML_CORP_PROVIDER, |r| spec_for(r, &email)).await
    else {
        panic!("expected failure without corpMail")
    };
}

#[tokio::test]
async fn acs_rejects_forged_stale_and_misdirected_responses() {
    let Some(s) = server().await else { return };
    let email = unique_email("saml-neg");

    // Bad requests.
    let resp = acs(s, None, "QUJD").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = acs(s, Some("no-such-flow"), "QUJD").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Missing SAMLResponse altogether.
    let resp = browser()
        .post(s.url("/auth/sso/saml/acs"))
        .form(&[("RelayState", "x")])
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error());
    // A flow of an OIDC provider cannot be completed on the ACS.
    let oidc_flow: SsoStartResponse = s
        .json(
            Method::GET,
            &format!("/auth/sso/{SSO_PROVIDER}/start"),
            None,
            NOBODY,
        )
        .await;
    let resp = acs(s, Some(&oidc_flow.flow_id), "QUJD").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(matches!(
        poll(s, &oidc_flow.flow_id).await,
        SsoResult::Failed { .. }
    ));

    type Shape<'a> = Box<dyn Fn(&Request) -> ResponseSpec + 'a>;
    let failing: Vec<(&str, Shape)> = vec![
        (
            "unsigned",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.sign_assertion = false;
                sp
            }),
        ),
        ("tampered", Box::new(|r| spec_for(r, &email))), // tampered below
        (
            "wrong InResponseTo",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.in_response_to = "_someone_elses_request".into();
                sp
            }),
        ),
        (
            "expired",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.not_on_or_after = Some(chrono::Utc::now() - chrono::Duration::hours(1));
                sp
            }),
        ),
        (
            "not yet valid",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.not_before = Some(chrono::Utc::now() + chrono::Duration::hours(1));
                sp
            }),
        ),
        (
            "wrong audience",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.audience = Some("https://another-sp.test".into());
                sp
            }),
        ),
        (
            "wrong recipient",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.recipient = Some("https://another-sp.test/acs".into());
                sp
            }),
        ),
        (
            "wrong destination",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.destination = Some("https://another-sp.test/acs".into());
                sp
            }),
        ),
        (
            "wrong issuer",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.idp_entity_id = "https://evil-idp.test".into();
                sp
            }),
        ),
        (
            "status failure",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.status = "urn:oasis:names:tc:SAML:2.0:status:Requester".into();
                sp
            }),
        ),
        (
            "encrypted for a provider without a key",
            Box::new(|r| {
                let mut sp = spec_for(r, &email);
                sp.encrypt_for = Some(saml_support::sp_public_key());
                sp
            }),
        ),
    ];
    for (name, shape) in failing {
        let flow = start(s, SAML_PROVIDER, None).await;
        let req = browser_leg(s, &flow).await;
        let mut xml = saml_support::build_response_xml(&shape(&req));
        if name == "tampered" {
            xml = xml.replace(&email, "mallory@test.local");
        }
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, xml);
        let resp = acs(s, Some(&flow.flow_id), &b64).await;
        assert_eq!(resp.status(), StatusCode::OK, "{name}");
        let SsoResult::Failed { message } = poll(s, &flow.flow_id).await else {
            panic!("{name}: expected failure")
        };
        if name == "status failure" {
            assert!(message.contains("Requester"), "{name}: {message}");
        } else {
            assert!(
                !message.contains(&email),
                "{name}: no reflection of the assertion in the message"
            );
        }
    }

    // Response signed by an unknown key (attacker with their own IdP cert).
    let flow = start(s, SAML_PROVIDER, None).await;
    let req = browser_leg(s, &flow).await;
    let mut spec = spec_for(&req, &email);
    spec.sign_assertion = false;
    let xml = saml_support::build_response_xml(&spec);
    let rid = Document::parse(&xml)
        .unwrap()
        .root_element()
        .attribute("ID")
        .unwrap()
        .to_string();
    let other = saml_support::random_key();
    let forged = termoso_server::saml::dsig::sign_enveloped(&xml, &rid, &other, None).unwrap();
    let resp = acs(
        s,
        Some(&flow.flow_id),
        &base64::Engine::encode(&base64::engine::general_purpose::STANDARD, forged),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(matches!(
        poll(s, &flow.flow_id).await,
        SsoResult::Failed { .. }
    ));

    // Sanity: the same shape, properly signed, succeeds.
    assert!(matches!(
        sign_in(s, SAML_PROVIDER, |r| spec_for(r, &email)).await,
        SsoResult::RegistrationRequired { .. }
    ));
}

#[tokio::test]
async fn acs_honours_the_redirect_chosen_at_start() {
    let Some(s) = server().await else { return };
    let email = unique_email("saml-redir");
    let target = format!("http://{}/cabinet/sso", s.addr);
    let flow = start(s, SAML_PROVIDER, Some(&target)).await;
    let req = browser_leg(s, &flow).await;
    let resp = acs(
        s,
        Some(&flow.flow_id),
        &saml_support::build_response_b64(&spec_for(&req, &email)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()["location"].to_str().unwrap(),
        format!("{target}?flow={}", flow.flow_id)
    );
    assert!(matches!(
        poll(s, &flow.flow_id).await,
        SsoResult::RegistrationRequired { .. }
    ));

    // Unsafe redirects are dropped and the done page is shown instead.
    let flow = start(s, SAML_PROVIDER, Some("https://evil.test/steal")).await;
    let req = browser_leg(s, &flow).await;
    let resp = acs(
        s,
        Some(&flow.flow_id),
        &saml_support::build_response_b64(&spec_for(&req, &email)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Status of an authenticated call with `token` (200 while the session lives).
async fn session_status(s: &TestServer, token: &str) -> StatusCode {
    s.call(Method::GET, "/account/sso", Some(token), NOBODY)
        .await
        .status()
}

/// `SessionIndex` of the assertion in a response we minted.
fn session_index_of(response_b64: &str) -> String {
    let xml = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, response_b64).unwrap(),
    )
    .unwrap();
    let marker = r#"SessionIndex=""#;
    let start = xml.find(marker).unwrap() + marker.len();
    let end = xml[start..].find('"').unwrap();
    xml[start..start + end].to_string()
}

/// Sign in through the IdP and finish with the password; returns the session
/// token and the IdP `SessionIndex` it is bound to.
async fn saml_login(s: &TestServer, email: &str, password: &str, dev: &str) -> (String, String) {
    let flow = start(s, SAML_PROVIDER, None).await;
    let req = browser_leg(s, &flow).await;
    let b64 = saml_support::build_response_b64(&spec_for(&req, email));
    let index = session_index_of(&b64);
    assert_eq!(
        acs(s, Some(&req.relay_state), &b64).await.status(),
        StatusCode::OK
    );
    let SsoResult::LoginRequired { sso_session, .. } = poll(s, &flow.flow_id).await else {
        panic!("expected login_required")
    };
    let AuthResponse::Authenticated(sess) =
        login_raw(s, email, password, device(dev), Some(sso_session))
            .await
            .unwrap()
    else {
        panic!("expected a session")
    };
    (sess.token, index)
}

async fn slo_get(s: &TestServer, query: &str) -> reqwest::Response {
    browser()
        .get(format!("{}?{query}", s.url("/auth/sso/saml/slo")))
        .header("x-forwarded-for", fake_ip())
        .send()
        .await
        .expect("slo")
}

#[tokio::test]
async fn idp_initiated_logout_revokes_saml_sessions() {
    let Some(s) = server().await else { return };
    let email = unique_email("slo");
    let password = "pw-slo-1234567890";
    let SsoResult::RegistrationRequired { sso_session, .. } =
        sign_in(s, SAML_PROVIDER, |r| spec_for(r, &email)).await
    else {
        panic!("expected registration_required")
    };
    let u = register_raw(s, &email, password, None, Some(sso_session)).await;
    let (phone, phone_index) = saml_login(s, &email, password, "slo phone").await;
    let (laptop, _) = saml_login(s, &email, password, "slo laptop").await;
    for t in [u.token(), &phone, &laptop] {
        assert_eq!(session_status(s, t).await, StatusCode::OK);
    }
    let slo_url = s.url("/auth/sso/saml/slo");

    // Unsigned and tampered requests change nothing.
    let (signed, _) =
        saml_support::logout_request_query(SAML_IDP_ENTITY, &slo_url, &email, None, None);
    let unsigned = signed.split("&SigAlg=").next().unwrap().to_string();
    assert_eq!(
        slo_get(s, &unsigned).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let mut tampered = signed.clone();
    tampered.replace_range(tampered.len() - 6.., "AAAAAA");
    assert_eq!(
        slo_get(s, &tampered).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(session_status(s, &phone).await, StatusCode::OK);

    // Narrowed to one IdP session: only the phone goes.
    let (q, req_id) = saml_support::logout_request_query(
        SAML_IDP_ENTITY,
        &slo_url,
        &email,
        Some(&phone_index),
        Some("relay-1"),
    );
    let resp = slo_get(s, &q).await;
    assert!(resp.status().is_redirection(), "{}", resp.status());
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(SAML_IDP_SLO_URL), "{location}");
    let (xml, relay) = saml_support::decode_redirect(&location);
    assert_eq!(relay, "relay-1");
    let doc = Document::parse(&xml).unwrap();
    let root = doc.root_element();
    assert_eq!(root.tag_name().name(), "LogoutResponse");
    assert_eq!(root.attribute("InResponseTo"), Some(req_id.as_str()));
    assert_eq!(root.attribute("Destination"), Some(SAML_IDP_SLO_URL));
    assert!(xml.contains("status:Success"));
    assert_eq!(session_status(s, &phone).await, StatusCode::UNAUTHORIZED);
    assert_eq!(session_status(s, &laptop).await, StatusCode::OK);
    assert_eq!(session_status(s, u.token()).await, StatusCode::OK);

    // No SessionIndex: every session this IdP opened for the subject.
    let (q, _) = saml_support::logout_request_query(SAML_IDP_ENTITY, &slo_url, &email, None, None);
    assert!(slo_get(s, &q).await.status().is_redirection());
    assert_eq!(session_status(s, &laptop).await, StatusCode::UNAUTHORIZED);
    assert_eq!(session_status(s, u.token()).await, StatusCode::UNAUTHORIZED);

    // A password-only session of the same user is not the IdP's to end.
    let plain = login(s, &email, password).await;
    let AuthResponse::Authenticated(plain) = plain else {
        panic!("expected a session")
    };
    let (q, _) = saml_support::logout_request_query(SAML_IDP_ENTITY, &slo_url, &email, None, None);
    assert!(slo_get(s, &q).await.status().is_redirection());
    assert_eq!(session_status(s, &plain.token).await, StatusCode::OK);
}

#[tokio::test]
async fn sp_initiated_logout_round_trips_through_the_idp() {
    let Some(s) = server().await else { return };
    let email = unique_email("slo-sp");
    let password = "pw-slo-sp-1234567890";
    let SsoResult::RegistrationRequired { sso_session, .. } =
        sign_in(s, SAML_PROVIDER, |r| spec_for(r, &email)).await
    else {
        panic!("expected registration_required")
    };
    let u = register_raw(s, &email, password, None, Some(sso_session)).await;
    let (token, index) = saml_login(s, &email, password, "slo desktop").await;

    let out: SsoLogoutResponse = s
        .json(Method::POST, "/auth/logout/sso", Some(&token), NOBODY)
        .await;
    let url = out.logout_url.expect("logout_url for a SAML session");
    assert!(url.starts_with(SAML_IDP_SLO_URL), "{url}");
    assert_eq!(session_status(s, &token).await, StatusCode::UNAUTHORIZED);
    let (xml, _) = saml_support::decode_redirect(&url);
    let doc = Document::parse(&xml).unwrap();
    let root = doc.root_element();
    assert_eq!(root.tag_name().namespace(), Some(NS_PROTOCOL));
    assert_eq!(root.tag_name().name(), "LogoutRequest");
    assert_eq!(root.attribute("Destination"), Some(SAML_IDP_SLO_URL));
    let text = |name: &str| {
        root.descendants()
            .find(|n| n.tag_name().name() == name)
            .and_then(|n| n.text())
            .map(str::to_string)
    };
    assert_eq!(text("NameID").as_deref(), Some(email.as_str()));
    assert_eq!(text("SessionIndex"), Some(index));
    let req_id = root.attribute("ID").unwrap().to_string();

    // The IdP answers; the answer is accepted once.
    let q = saml_support::logout_response_query(
        SAML_IDP_ENTITY,
        &s.url("/auth/sso/saml/slo"),
        &req_id,
        None,
    );
    let resp = slo_get(s, &q).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.text().await.unwrap().contains("Signed out"));
    assert_eq!(slo_get(s, &q).await.status(), StatusCode::UNAUTHORIZED);

    // A password-only session did not come from the IdP: nothing to end there.
    let AuthResponse::Authenticated(plain) = login(s, &email, password).await else {
        panic!("expected a session")
    };
    let out: SsoLogoutResponse = s
        .json(Method::POST, "/auth/logout/sso", Some(&plain.token), NOBODY)
        .await;
    assert!(out.logout_url.is_none());
    assert_eq!(
        session_status(s, &plain.token).await,
        StatusCode::UNAUTHORIZED
    );
    // The registration itself was vouched for by the IdP, so that session is SAML-bound.
    let out: SsoLogoutResponse = s
        .json(Method::POST, "/auth/logout/sso", Some(u.token()), NOBODY)
        .await;
    assert!(out.logout_url.is_some());
}
