//! Gateway relay: a bridge in gateway mode accepts tunnels for members of its
//! vaults; bytes are relayed verbatim; strangers and offline gateways are refused.

mod common;

use common::*;
use futures::{SinkExt, StreamExt};
use reqwest::Method;
use termoso_crypto::keys::{KeyPair, SymmetricKey};
use termoso_crypto::sealed;
use termoso_proto::bridge::{BridgeVaultKey, CreateBridgeRequest};
use termoso_proto::vault::{CreateVaultRequest, VaultMemberUpsert, VaultRole};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

async fn text(
    ws: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
) -> serde_json::Value {
    loop {
        match ws.next().await.expect("frame").expect("ws ok") {
            Message::Text(t) => return serde_json::from_str(&t).unwrap(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn gateway_relays_for_vault_members_only() {
    let Some(s) = server().await else { return };
    let owner = register(s, &unique_email("owner"), "pw-owner-1234567").await;
    let stranger = register(s, &unique_email("stranger"), "pw-str-123456789").await;
    let team: serde_json::Value = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Ops" })),
        )
        .await;
    let team_id = team["id"].as_str().unwrap().to_string();
    let key = SymmetricKey::generate();
    let vault: serde_json::Value = s
        .json(
            Method::POST,
            &format!("/teams/{team_id}/vaults"),
            Some(owner.token()),
            Some(&CreateVaultRequest {
                name: "Lab".into(),
                members: vec![VaultMemberUpsert {
                    user_id: owner.id(),
                    role: VaultRole::Manager,
                    sealed_key: sealed::seal_vault_key(owner.keypair.public(), &key).unwrap(),
                }],
            }),
        )
        .await;
    let vault_id: Uuid = vault["id"].as_str().unwrap().parse().unwrap();
    let kp = KeyPair::generate();
    let created: serde_json::Value = s
        .json(
            Method::POST,
            "/account/bridges",
            Some(owner.token()),
            Some(&CreateBridgeRequest {
                name: "lab-gw".into(),
                public_key: kp.public_b64(),
                vaults: vec![BridgeVaultKey {
                    vault_id,
                    sealed_key: sealed::seal_vault_key(kp.public(), &key).unwrap(),
                }],
            }),
        )
        .await;
    let gateway_id = created["bridge"]["id"].as_str().unwrap().to_string();
    let bridge_token = created["token"].as_str().unwrap().to_string();
    let host_id = Uuid::new_v4();

    // Offline: refused at once.
    let client_url = format!("ws://{}/api/v1/gateways/{gateway_id}/connect", s.addr);
    let (mut c, _) = tokio_tungstenite::connect_async(&client_url).await.unwrap();
    c.send(Message::Text(
        serde_json::json!({ "token": owner.token(), "vault_id": vault_id, "host_id": host_id })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let err = text(&mut c).await;
    assert_eq!(err["code"], "gateway_offline", "{err}");

    // The gateway comes online.
    let (mut g, _) =
        tokio_tungstenite::connect_async(format!("ws://{}/api/v1/gateways/ws", s.addr))
            .await
            .unwrap();
    g.send(Message::Text(
        serde_json::json!({ "token": bridge_token })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let hello = text(&mut g).await;
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["gateway_id"], gateway_id);
    let list: serde_json::Value = s
        .json(Method::GET, "/gateways", Some(owner.token()), NOBODY)
        .await;
    assert_eq!(list["gateways"][0]["id"], gateway_id, "{list}");
    assert_eq!(list["gateways"][0]["online"], true);
    let none: serde_json::Value = s
        .json(Method::GET, "/gateways", Some(stranger.token()), NOBODY)
        .await;
    assert!(none["gateways"].as_array().unwrap().is_empty());

    // A stranger is refused; the gateway never hears about it.
    let (mut c, _) = tokio_tungstenite::connect_async(&client_url).await.unwrap();
    c.send(Message::Text(
        serde_json::json!({ "token": stranger.token(), "vault_id": vault_id, "host_id": host_id })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    assert_eq!(text(&mut c).await["code"], "forbidden");

    // The owner connects: open → accept → echo.
    let (mut c, _) = tokio_tungstenite::connect_async(&client_url).await.unwrap();
    c.send(Message::Text(
        serde_json::json!({ "token": owner.token(), "vault_id": vault_id, "host_id": host_id })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let open = text(&mut g).await;
    assert_eq!(open["type"], "open", "{open}");
    assert_eq!(open["vault_id"], vault_id.to_string());
    assert_eq!(open["host_id"], host_id.to_string());
    let conn_id: Uuid = open["conn_id"].as_str().unwrap().parse().unwrap();
    let frame = |kind: u8, data: &[u8]| {
        let mut out = conn_id.as_bytes().to_vec();
        out.push(kind);
        out.extend_from_slice(data);
        Message::Binary(out.into())
    };
    g.send(frame(1, b"")).await.unwrap();
    assert_eq!(text(&mut c).await["type"], "accepted");
    c.send(Message::Binary(b"SSH-2.0-client".to_vec().into()))
        .await
        .unwrap();
    let to_gw = loop {
        match g.next().await.unwrap().unwrap() {
            Message::Binary(b) => break b,
            _ => continue,
        }
    };
    assert_eq!(&to_gw[..16], conn_id.as_bytes());
    assert_eq!(to_gw[16], 3);
    assert_eq!(&to_gw[17..], b"SSH-2.0-client");
    g.send(frame(4, b"SSH-2.0-OpenSSH")).await.unwrap();
    let back = loop {
        match c.next().await.unwrap().unwrap() {
            Message::Binary(b) => break b,
            _ => continue,
        }
    };
    assert_eq!(&back[..], b"SSH-2.0-OpenSSH");
    // Gateway closes → client socket ends.
    g.send(frame(5, b"")).await.unwrap();
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match c.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                _ => continue,
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "client not closed");
    let audit: serde_json::Value = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/audit?action=gateway.connected"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(
        audit["events"][0]["details"]["gateway_id"], gateway_id,
        "{audit}"
    );
}
