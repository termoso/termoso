//! Team SSH CA: lifecycle, issuing, principals, rotation, revocation and
//! the public trusted-keys text.

mod common;

use common::*;
use reqwest::{Method, StatusCode};
use ssh_key::certificate::CertType;
use ssh_key::{Certificate, HashAlg, PrivateKey, PublicKey};
use termoso_proto::auth::{AuthResponse, DeviceApproveRequest};
use termoso_proto::ca::*;
use termoso_proto::sshid::SshIdKeyType;

macro_rules! server {
    () => {
        match server().await {
            Some(s) => s,
            None => return,
        }
    };
}

async fn team_with_owner(s: &TestServer) -> (User, String) {
    let owner = register(s, &unique_email("ca-owner"), "pw-owner-1234567").await;
    let team: serde_json::Value = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Ops" })),
        )
        .await;
    (owner, team["id"].as_str().unwrap().to_string())
}

fn device_key(seed: u8) -> String {
    let kp = ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]);
    PrivateKey::from(kp).public_key().to_openssh().unwrap()
}

async fn public_text(s: &TestServer, path: &str) -> (StatusCode, String) {
    let resp = s
        .http()
        .get(format!("http://{}{path}", s.addr))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.text().await.unwrap())
}

#[tokio::test]
async fn ca_lifecycle_issue_rotate_revoke() {
    let s = server!();
    let (owner, team_id) = team_with_owner(s).await;
    let t = |p: &str| format!("/teams/{team_id}/ca{p}");

    // No CA yet: 404 on the team route and on the public text.
    s.expect_status::<()>(
        Method::GET,
        &t(""),
        Some(owner.token()),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
    let (status, _) = public_text(s, &format!("/ca/{team_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Bad input is rejected before anything is created.
    s.expect_status(
        Method::PUT,
        &t(""),
        Some(owner.token()),
        Some(&serde_json::json!({ "principals": ["Root"] })),
        StatusCode::BAD_REQUEST,
    )
    .await;
    s.expect_status(
        Method::PUT,
        &t(""),
        Some(owner.token()),
        Some(&serde_json::json!({ "ttl_hours": 0 })),
        StatusCode::BAD_REQUEST,
    )
    .await;
    s.expect_status(
        Method::PUT,
        &t(""),
        Some(owner.token()),
        Some(&serde_json::json!({ "extensions": ["permit-everything"] })),
        StatusCode::BAD_REQUEST,
    )
    .await;

    // Create.
    let ca: TeamCa = s
        .json(
            Method::PUT,
            &t(""),
            Some(owner.token()),
            Some(&UpdateTeamCaRequest {
                principals: Some(vec!["ubuntu".into(), "deploy".into(), "ubuntu".into()]),
                ttl_hours: Some(4),
                ..Default::default()
            }),
        )
        .await;
    assert_eq!(ca.key_type, "ssh-ed25519");
    assert!(ca.public_key.starts_with("ssh-ed25519 "));
    assert!(ca.fingerprint.starts_with("SHA256:"));
    assert_eq!(ca.principals, vec!["ubuntu", "deploy"]);
    assert_eq!(ca.ttl_hours, 4);
    assert_eq!(ca.extensions, EXTENSIONS_DEFAULT);
    assert!(ca.enabled);
    assert!(ca.retired_public_key.is_none());
    assert_eq!(ca.active_certificates, 0);
    assert!(ca.trusted_keys_url.ends_with(&format!("/ca/{team_id}")));
    let ca_fp = PublicKey::from_openssh(&ca.public_key)
        .unwrap()
        .fingerprint(HashAlg::Sha256);

    // Public text carries the key.
    let (status, text) = public_text(s, &format!("/ca/{team_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(text.contains(&ca.public_key), "{text}");

    // Issue for this device's key, all principals.
    let pk = device_key(1);
    let issued: IssueCertificateResponse = s
        .json(
            Method::POST,
            &t("/issue"),
            Some(owner.token()),
            Some(&IssueCertificateRequest {
                public_key: pk.clone(),
                principals: vec![],
            }),
        )
        .await;
    let cert = Certificate::from_openssh(&issued.certificate).unwrap();
    assert_eq!(cert.cert_type(), CertType::User);
    assert_eq!(cert.valid_principals(), &["ubuntu", "deploy"]);
    assert!(cert.key_id().contains(&owner.email), "{}", cert.key_id());
    assert_eq!(cert.serial(), issued.issued.serial as u64);
    assert!(cert.extensions().contains_key("permit-pty"));
    assert!(!cert.extensions().contains_key("permit-agent-forwarding"));
    cert.validate(&[ca_fp]).expect("signed by the team CA");
    let lifetime = issued.issued.valid_before - issued.issued.valid_after;
    assert!(lifetime.num_minutes() >= 4 * 60 && lifetime.num_minutes() <= 4 * 60 + 1);
    assert_eq!(issued.issued.key_type, SshIdKeyType::Ed25519);
    assert!(issued.issued.active && issued.issued.current_device);
    assert_eq!(issued.ca_public_key, ca.public_key);
    assert_eq!(
        issued.issued.key_fingerprint,
        PublicKey::from_openssh(&pk)
            .unwrap()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    );

    // A subset of principals is fine, an unknown one is not.
    let sub: IssueCertificateResponse = s
        .json(
            Method::POST,
            &t("/issue"),
            Some(owner.token()),
            Some(&IssueCertificateRequest {
                public_key: pk.clone(),
                principals: vec!["deploy".into()],
            }),
        )
        .await;
    assert_eq!(sub.issued.principals, vec!["deploy"]);
    s.expect_status(
        Method::POST,
        &t("/issue"),
        Some(owner.token()),
        Some(&IssueCertificateRequest {
            public_key: pk.clone(),
            principals: vec!["root".into()],
        }),
        StatusCode::BAD_REQUEST,
    )
    .await;
    // Not a key, and a hardware key type.
    s.expect_status(
        Method::POST,
        &t("/issue"),
        Some(owner.token()),
        Some(&IssueCertificateRequest {
            public_key: "ssh-ed25519 not-base64".into(),
            principals: vec![],
        }),
        StatusCode::BAD_REQUEST,
    )
    .await;

    // Listing and counters.
    let list: IssuedCertificateList = s
        .json::<(), _>(Method::GET, &t("/certificates"), Some(owner.token()), None)
        .await;
    assert_eq!(list.certificates.len(), 2);
    let ca: TeamCa = s
        .json::<(), _>(Method::GET, &t(""), Some(owner.token()), None)
        .await;
    assert_eq!(ca.active_certificates, 2);

    // Revoke the second one: shows up in the KRL spec, counter drops.
    let revoked: IssuedCertificate = s
        .json::<(), _>(
            Method::POST,
            &t(&format!("/certificates/{}/revoke", sub.issued.id)),
            Some(owner.token()),
            None,
        )
        .await;
    assert!(revoked.revoked_at.is_some() && !revoked.active);
    let resp = s
        .call::<()>(Method::GET, &t("/revoked"), Some(owner.token()), None)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let krl = resp.text().await.unwrap();
    assert!(
        krl.contains(&format!("serial: {}", sub.issued.serial)),
        "{krl}"
    );
    assert!(
        !krl.contains(&format!("serial: {}", issued.issued.serial)),
        "{krl}"
    );
    let ca: TeamCa = s
        .json::<(), _>(Method::GET, &t(""), Some(owner.token()), None)
        .await;
    assert_eq!(ca.active_certificates, 1);

    // Rotate: new key, old one retired but still published; new certificates
    // validate against the new key only.
    let rotated: TeamCa = s
        .json(
            Method::POST,
            &t("/rotate"),
            Some(owner.token()),
            Some(&RotateTeamCaRequest {
                grace_hours: Some(2),
            }),
        )
        .await;
    assert_ne!(rotated.public_key, ca.public_key);
    assert_eq!(
        rotated.retired_public_key.as_deref(),
        Some(ca.public_key.as_str())
    );
    assert!(rotated.retired_until.is_some() && rotated.rotated_at.is_some());
    let (_, text) = public_text(s, &format!("/ca/{team_id}")).await;
    assert!(
        text.contains(&rotated.public_key) && text.contains(&ca.public_key),
        "{text}"
    );
    let fresh: IssueCertificateResponse = s
        .json(
            Method::POST,
            &t("/issue"),
            Some(owner.token()),
            Some(&IssueCertificateRequest {
                public_key: pk.clone(),
                principals: vec![],
            }),
        )
        .await;
    let cert = Certificate::from_openssh(&fresh.certificate).unwrap();
    assert!(cert.validate(&[ca_fp]).is_err());
    let new_fp = PublicKey::from_openssh(&rotated.public_key)
        .unwrap()
        .fingerprint(HashAlg::Sha256);
    cert.validate(&[new_fp]).expect("signed by the rotated key");

    // Disabled: no issuing, no public text.
    let off: TeamCa = s
        .json(
            Method::PUT,
            &t(""),
            Some(owner.token()),
            Some(&UpdateTeamCaRequest {
                enabled: Some(false),
                ..Default::default()
            }),
        )
        .await;
    assert!(!off.enabled);
    s.expect_status(
        Method::POST,
        &t("/issue"),
        Some(owner.token()),
        Some(&IssueCertificateRequest {
            public_key: pk.clone(),
            principals: vec![],
        }),
        StatusCode::CONFLICT,
    )
    .await;
    let (status, _) = public_text(s, &format!("/ca/{team_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Outsiders see nothing.
    let stranger = register(s, &unique_email("ca-stranger"), "pw-stranger-1234567").await;
    s.expect_status::<()>(
        Method::GET,
        &t(""),
        Some(stranger.token()),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;

    // Delete wipes the CA and its records.
    s.expect_status::<()>(
        Method::DELETE,
        &t(""),
        Some(owner.token()),
        None,
        StatusCode::NO_CONTENT,
    )
    .await;
    s.expect_status::<()>(
        Method::GET,
        &t(""),
        Some(owner.token()),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
}

/// Logging the device out everywhere revokes its live certificates.
#[tokio::test]
async fn device_revocation_revokes_certificates() {
    let s = server!();
    let (owner, team_id) = team_with_owner(s).await;
    let t = |p: &str| format!("/teams/{team_id}/ca{p}");
    let _: TeamCa = s
        .json(
            Method::PUT,
            &t(""),
            Some(owner.token()),
            Some(&UpdateTeamCaRequest {
                principals: Some(vec!["ubuntu".into()]),
                ..Default::default()
            }),
        )
        .await;
    // A second device of the same account asks for a certificate.
    // A new device of the owner's account signs in (email approval) and
    // asks for a certificate.
    let second = match login_raw(s, &owner.email, &owner.password, device("phone"), None)
        .await
        .expect("login")
    {
        AuthResponse::Authenticated(session) => session,
        AuthResponse::DeviceApprovalRequired { approval_token, .. } => {
            let code = s.emailed_code(&owner.email, "new device sign-in").await;
            let approved: AuthResponse = s
                .json(
                    Method::POST,
                    "/auth/device/approve",
                    None,
                    Some(&DeviceApproveRequest {
                        approval_token,
                        code,
                    }),
                )
                .await;
            let AuthResponse::Authenticated(session) = approved else {
                panic!("device approval did not yield a session: {approved:?}");
            };
            session
        }
        other => panic!("unexpected sign-in outcome: {other:?}"),
    };
    let issued: IssueCertificateResponse = s
        .json(
            Method::POST,
            &t("/issue"),
            Some(&second.token),
            Some(&IssueCertificateRequest {
                public_key: device_key(9),
                principals: vec![],
            }),
        )
        .await;
    assert!(issued.issued.active);
    let device_id = issued.issued.device_id.expect("device");
    // The owner's first device revokes the phone.
    s.expect_status::<()>(
        Method::DELETE,
        &format!("/account/devices/{device_id}"),
        Some(owner.token()),
        None,
        StatusCode::NO_CONTENT,
    )
    .await;
    let list: IssuedCertificateList = s
        .json::<(), _>(Method::GET, &t("/certificates"), Some(owner.token()), None)
        .await;
    let c = list
        .certificates
        .iter()
        .find(|c| c.id == issued.issued.id)
        .unwrap();
    assert!(c.revoked_at.is_some() && !c.active);
}
