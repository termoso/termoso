//! `offset` / `limit` on team lists: whole list without `limit`, pages with
//! `total` when given, filters on devices / access requests.

mod common;
use common::*;
use reqwest::{Method, StatusCode};
use termoso_proto::admin::{AdminTeamAuditList, AdminTeamMemberList};
use termoso_proto::logs::LogListResponse;
use termoso_proto::team::{InviteList, TeamMemberList};
use uuid::Uuid;

#[tokio::test]
async fn invites_and_members_page_with_totals() {
    let Some(s) = server().await else { return };
    let owner = register(s, &unique_email("pg-owner"), "pw-owner-1234567").await;
    let team: serde_json::Value = s
        .json(
            Method::POST,
            "/teams",
            Some(owner.token()),
            Some(&serde_json::json!({ "name": "Paging" })),
        )
        .await;
    let team_id: Uuid = team["id"].as_str().unwrap().parse().unwrap();
    for i in 0..3 {
        let _: serde_json::Value = s
            .json(
                Method::POST,
                &format!("/teams/{team_id}/invites"),
                Some(owner.token()),
                Some(&serde_json::json!({
                    "email": unique_email(&format!("pg-inv{i}")), "role": "member", "vault_ids": []
                })),
            )
            .await;
    }

    // No `limit`: the whole list, as before paging existed.
    let all: InviteList = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/invites"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(all.invites.len(), 3);
    assert_eq!(all.total, 3);

    let page: InviteList = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/invites?limit=2"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(page.invites.len(), 2);
    assert_eq!(page.total, 3);
    let last: InviteList = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/invites?limit=2&offset=2"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(last.invites.len(), 1);
    assert_eq!(last.total, 3);
    assert_ne!(last.invites[0].id, page.invites[0].id);

    let members: TeamMemberList = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/members?limit=1"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert_eq!(members.members.len(), 1);
    assert_eq!(members.total, 1);

    // Team recordings use the vault-listing envelope the clients parse.
    let logs: LogListResponse = s
        .json(
            Method::GET,
            &format!("/teams/{team_id}/logs?limit=5"),
            Some(owner.token()),
            NOBODY,
        )
        .await;
    assert!(logs.logs.is_empty());
    assert_eq!(logs.total, 0);
    assert!(!logs.has_more);

    // Bad filter values are rejected, not silently ignored.
    s.expect_status(
        Method::GET,
        &format!("/teams/{team_id}/devices?status=bogus"),
        Some(owner.token()),
        NOBODY,
        StatusCode::BAD_REQUEST,
    )
    .await;
    s.expect_status(
        Method::GET,
        &format!("/teams/{team_id}/access-requests?status=bogus"),
        Some(owner.token()),
        NOBODY,
        StatusCode::BAD_REQUEST,
    )
    .await;

    // Admin console: paged members and audit for one team.
    let admin = admin_token(s).await;
    let am: AdminTeamMemberList = s
        .json(
            Method::GET,
            &format!("/admin/teams/{team_id}/members?limit=1"),
            Some(&admin),
            NOBODY,
        )
        .await;
    assert_eq!(am.members.len(), 1);
    assert_eq!(am.total, 1);
    let none: AdminTeamMemberList = s
        .json(
            Method::GET,
            &format!("/admin/teams/{team_id}/members?q=nobody-matches-this"),
            Some(&admin),
            NOBODY,
        )
        .await;
    assert!(none.members.is_empty());
    let audit: AdminTeamAuditList = s
        .json(
            Method::GET,
            &format!("/admin/teams/{team_id}/audit?limit=1"),
            Some(&admin),
            NOBODY,
        )
        .await;
    assert_eq!(audit.events.as_array().map(Vec::len), Some(1));
    assert!(audit.total >= 3, "team.created + invites: {}", audit.total);
    s.expect_status(
        Method::GET,
        &format!("/admin/teams/{}/audit", Uuid::new_v4()),
        Some(&admin),
        NOBODY,
        StatusCode::NOT_FOUND,
    )
    .await;
}
