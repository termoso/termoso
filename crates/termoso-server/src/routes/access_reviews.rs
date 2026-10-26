//! Periodic access reviews: "are these people still supposed to be here?"
//!
//! A review snapshots every non-owner team membership and every team-vault
//! access; an admin marks each line `keep` or `remove`, and completing the
//! review applies the removals through the same paths a manual removal uses
//! (so the audit log and webhooks see `member.removed` / `vault.access_revoked`
//! as usual, tagged with the review). Reviews open by hand or on the cadence
//! in the `access_review_days` policy; owners and admins are e-mailed when one
//! opens and once it is overdue.

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use termoso_proto::team::{
    AccessReview, AccessReviewDetail, AccessReviewItem, AccessReviewList,
    CompleteAccessReviewRequest, DecideAccessReviewItemRequest,
};
use uuid::Uuid;

use crate::audit;
use crate::error::{ApiResult, Error};
use crate::extract::Auth;
use crate::state::AppState;

/// How long a review may stay open before owners/admins get a reminder.
const DUE_AFTER_DAYS: i32 = 14;
const NOTE_MAX: usize = 500;
const SCHEDULER_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);

type ReviewRow = (
    Uuid,
    Uuid,
    String,
    Option<Uuid>,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    i32,
    i32,
    i64,
    i64,
);

macro_rules! review_select {
    ($tail:literal) => {
        concat!(
            "SELECT r.id, r.team_id, r.status, r.opened_by, r.opened_at, r.due_at, r.closed_by, r.closed_at,
                    r.kept, r.removed,
                    (SELECT count(*) FROM team_access_review_items i WHERE i.review_id = r.id),
                    (SELECT count(*) FROM team_access_review_items i WHERE i.review_id = r.id AND i.decision IS NOT NULL)
             FROM team_access_reviews r ",
            $tail
        )
    };
}

fn review(r: ReviewRow) -> AccessReview {
    let (
        id,
        team_id,
        status,
        opened_by,
        opened_at,
        due_at,
        closed_by,
        closed_at,
        kept,
        removed,
        items,
        decided,
    ) = r;
    AccessReview {
        id,
        team_id,
        status,
        opened_by,
        opened_at,
        due_at,
        closed_by,
        closed_at,
        items,
        decided,
        kept,
        removed,
    }
}

async fn load(state: &AppState, team_id: Uuid, rid: Uuid) -> ApiResult<AccessReview> {
    let row: Option<ReviewRow> =
        sqlx::query_as(review_select!("WHERE r.team_id = $1 AND r.id = $2"))
            .bind(team_id)
            .bind(rid)
            .fetch_optional(&state.db)
            .await?;
    row.map(review)
        .ok_or_else(|| Error::not_found("Access review"))
}

type ItemRow = (
    Uuid,
    String,
    Uuid,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    String,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<String>,
);

async fn items(state: &AppState, rid: Uuid) -> ApiResult<Vec<AccessReviewItem>> {
    let rows: Vec<ItemRow> = sqlx::query_as(
        "SELECT i.id, i.kind, i.user_id, u.email, u.display_name, i.vault_id, v.name, i.role,
                i.last_seen_at, i.decision, i.decided_by, i.decided_at, i.note
         FROM team_access_review_items i
         LEFT JOIN users u ON u.id = i.user_id
         LEFT JOIN vaults v ON v.id = i.vault_id
         WHERE i.review_id = $1
         ORDER BY i.kind, lower(coalesce(u.email, '')), v.name",
    )
    .bind(rid)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                kind,
                user_id,
                email,
                display_name,
                vault_id,
                vault_name,
                role,
                last_seen_at,
                decision,
                decided_by,
                decided_at,
                note,
            )| AccessReviewItem {
                id,
                kind,
                user_id,
                email,
                display_name,
                vault_id,
                vault_name,
                role,
                last_seen_at,
                decision,
                decided_by,
                decided_at,
                note,
            },
        )
        .collect())
}

/// `GET /teams/{id}/access-reviews` (`members.view`).
#[utoipa::path(get, path = "/api/v1/teams/{id}/access-reviews", tag = "teams",
    params(("id" = Uuid, Path)), responses((status = 200, body = AccessReviewList)))]
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Json<AccessReviewList>> {
    crate::authz::require(&state, team_id, auth.user_id(), "members.view").await?;
    let rows: Vec<ReviewRow> = sqlx::query_as(review_select!(
        "WHERE r.team_id = $1 ORDER BY r.opened_at DESC LIMIT 100"
    ))
    .bind(team_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(AccessReviewList {
        reviews: rows.into_iter().map(review).collect(),
    }))
}

/// `GET /teams/{id}/access-reviews/{rid}` (`members.view`).
#[utoipa::path(get, path = "/api/v1/teams/{id}/access-reviews/{rid}", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path)), responses((status = 200, body = AccessReviewDetail)))]
pub async fn get(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, rid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<AccessReviewDetail>> {
    crate::authz::require(&state, team_id, auth.user_id(), "members.view").await?;
    let review = load(&state, team_id, rid).await?;
    let items = items(&state, rid).await?;
    Ok(Json(AccessReviewDetail { review, items }))
}

/// `POST /teams/{id}/access-reviews` — open a review now (`members.remove`);
/// 409 while one is open.
#[utoipa::path(post, path = "/api/v1/teams/{id}/access-reviews", tag = "teams",
    params(("id" = Uuid, Path)), responses((status = 200, body = AccessReviewDetail), (status = 409)))]
pub async fn open(
    State(state): State<AppState>,
    auth: Auth,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Json<AccessReviewDetail>> {
    crate::authz::require(&state, team_id, auth.user_id(), "members.remove").await?;
    let rid = open_review(&state, team_id, Some(auth.user_id()))
        .await?
        .ok_or_else(|| Error::conflict("An access review is already open"))?;
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "access_review.opened")
            .details(serde_json::json!({ "review_id": rid, "scheduled": false })),
    )
    .await;
    let review = load(&state, team_id, rid).await?;
    let items = items(&state, rid).await?;
    Ok(Json(AccessReviewDetail { review, items }))
}

/// Snapshot the team into a new open review; `None` if one is already open.
pub(crate) async fn open_review(
    state: &AppState,
    team_id: Uuid,
    opened_by: Option<Uuid>,
) -> ApiResult<Option<Uuid>> {
    let rid = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO team_access_reviews (id, team_id, opened_by, due_at)
         SELECT $1, $2, $3, now() + make_interval(days => $4)
         WHERE NOT EXISTS (SELECT 1 FROM team_access_reviews WHERE team_id = $2 AND status = 'open')",
    )
    .bind(rid)
    .bind(team_id)
    .bind(opened_by)
    .bind(DUE_AFTER_DAYS)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Ok(None);
    }
    // Memberships (owners are never up for review) with the latest sign of life.
    sqlx::query(
        "INSERT INTO team_access_review_items (id, review_id, kind, user_id, role, last_seen_at)
         SELECT gen_random_uuid(), $1, 'member', m.user_id, m.role,
                (SELECT max(d.last_seen_at) FROM devices d WHERE d.user_id = m.user_id)
         FROM team_members m WHERE m.team_id = $2 AND m.role <> 'owner'",
    )
    .bind(rid)
    .bind(team_id)
    .execute(&mut *tx)
    .await?;
    // Access to team vaults, same exclusion.
    sqlx::query(
        "INSERT INTO team_access_review_items (id, review_id, kind, user_id, vault_id, role, last_seen_at)
         SELECT gen_random_uuid(), $1, 'vault_access', vm.user_id, vm.vault_id, vm.role,
                (SELECT max(d.last_seen_at) FROM devices d WHERE d.user_id = vm.user_id)
         FROM vault_members vm JOIN vaults v ON v.id = vm.vault_id
         WHERE v.team_id = $2
           AND NOT EXISTS (SELECT 1 FROM team_members o
                           WHERE o.team_id = $2 AND o.user_id = vm.user_id AND o.role = 'owner')",
    )
    .bind(rid)
    .bind(team_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(rid))
}

/// `POST /teams/{id}/access-reviews/{rid}/items/{iid}` — decide one line (`members.remove`).
#[utoipa::path(post, path = "/api/v1/teams/{id}/access-reviews/{rid}/items/{iid}", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path), ("iid" = Uuid, Path)),
    request_body = DecideAccessReviewItemRequest, responses((status = 200, body = AccessReviewItem)))]
pub async fn decide(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, rid, iid)): Path<(Uuid, Uuid, Uuid)>,
    Json(req): Json<DecideAccessReviewItemRequest>,
) -> ApiResult<Json<AccessReviewItem>> {
    crate::authz::require(&state, team_id, auth.user_id(), "members.remove").await?;
    if !matches!(req.decision.as_str(), "keep" | "remove") {
        return Err(Error::bad_request("decision must be keep or remove"));
    }
    let note = req
        .note
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    if note.as_ref().is_some_and(|n| n.chars().count() > NOTE_MAX) {
        return Err(Error::bad_request("note too long"));
    }
    let r = load(&state, team_id, rid).await?;
    if r.status != "open" {
        return Err(Error::conflict("This review is closed"));
    }
    let (user_id, kind): (Uuid, String) = sqlx::query_as(
        "UPDATE team_access_review_items SET decision = $3, decided_by = $4, decided_at = now(), note = $5
         WHERE id = $1 AND review_id = $2 RETURNING user_id, kind",
    )
    .bind(iid)
    .bind(rid)
    .bind(&req.decision)
    .bind(auth.user_id())
    .bind(&note)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| Error::not_found("Review item"))?;
    if kind == "member" && user_id == auth.user_id() && req.decision == "remove" {
        // Undo: nobody removes themselves through a review.
        sqlx::query("UPDATE team_access_review_items SET decision = NULL, decided_by = NULL, decided_at = NULL WHERE id = $1")
            .bind(iid)
            .execute(&state.db)
            .await?;
        return Err(Error::bad_request("You cannot remove yourself in a review"));
    }
    let all = items(&state, rid).await?;
    all.into_iter()
        .find(|i| i.id == iid)
        .map(Json)
        .ok_or_else(|| Error::not_found("Review item"))
}

/// `POST /teams/{id}/access-reviews/{rid}/complete` — apply removals (`members.remove`).
/// 409 while lines are undecided unless `undecided = "keep"`.
#[utoipa::path(post, path = "/api/v1/teams/{id}/access-reviews/{rid}/complete", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path)),
    request_body = CompleteAccessReviewRequest, responses((status = 200, body = AccessReview), (status = 409)))]
pub async fn complete(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, rid)): Path<(Uuid, Uuid)>,
    Json(req): Json<CompleteAccessReviewRequest>,
) -> ApiResult<Json<AccessReview>> {
    crate::authz::require(&state, team_id, auth.user_id(), "members.remove").await?;
    let r = load(&state, team_id, rid).await?;
    if r.status != "open" {
        return Err(Error::conflict("This review is closed"));
    }
    let keep_undecided = match req.undecided.as_deref() {
        None => false,
        Some("keep") => true,
        Some(_) => return Err(Error::bad_request("undecided must be keep")),
    };
    if !keep_undecided && r.decided < r.items {
        return Err(Error::conflict(format!(
            "{} of {} lines are undecided",
            r.items - r.decided,
            r.items
        )));
    }
    if keep_undecided {
        sqlx::query(
            "UPDATE team_access_review_items SET decision = 'keep', decided_by = $2, decided_at = now()
             WHERE review_id = $1 AND decision IS NULL",
        )
        .bind(rid)
        .bind(auth.user_id())
        .execute(&state.db)
        .await?;
    }
    let removals: Vec<(Uuid, String, Uuid, Option<Uuid>, String)> = sqlx::query_as(
        "SELECT id, kind, user_id, vault_id, role FROM team_access_review_items
         WHERE review_id = $1 AND decision = 'remove' ORDER BY kind DESC",
    )
    .bind(rid)
    .fetch_all(&state.db)
    .await?;
    let mut removed = 0;
    for (_, kind, user_id, vault_id, role) in &removals {
        match (kind.as_str(), vault_id) {
            ("member", _) => {
                // Still a member? (A vault_access removal for the same user is moot once they are out.)
                if super::teams::my_role(&state.db, team_id, *user_id)
                    .await
                    .is_err()
                {
                    continue;
                }
                let converted = super::teams::remove(&state, team_id, *user_id).await?;
                audit::record(
                    &state.db,
                    audit::Entry::new(team_id, &auth, "member.removed")
                        .user(*user_id)
                        .details(serde_json::json!({
                            "role": role, "review_id": rid,
                            "account": if converted { "converted" } else { "kept" },
                        })),
                )
                .await;
                removed += 1;
            }
            ("vault_access", Some(vid)) => {
                let n = sqlx::query(
                    "DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2
                     AND EXISTS (SELECT 1 FROM vaults v WHERE v.id = $1 AND v.team_id = $3)",
                )
                .bind(vid)
                .bind(user_id)
                .bind(team_id)
                .execute(&state.db)
                .await?
                .rows_affected();
                if n > 0 {
                    audit::record(
                        &state.db,
                        audit::Entry::new(team_id, &auth, "vault.access_revoked")
                            .vault(*vid)
                            .user(*user_id)
                            .details(serde_json::json!({ "role": role, "review_id": rid })),
                    )
                    .await;
                    removed += 1;
                }
            }
            _ => {}
        }
    }
    sqlx::query(
        "UPDATE team_access_reviews SET status = 'completed', closed_by = $2, closed_at = now(),
            kept = (SELECT count(*) FROM team_access_review_items WHERE review_id = $1 AND decision = 'keep'),
            removed = $3
         WHERE id = $1",
    )
    .bind(rid)
    .bind(auth.user_id())
    .bind(removed)
    .execute(&state.db)
    .await?;
    let done = load(&state, team_id, rid).await?;
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "access_review.completed").details(serde_json::json!({
            "review_id": rid, "kept": done.kept, "removed": done.removed, "lines": done.items,
        })),
    )
    .await;
    Ok(Json(done))
}

/// `POST /teams/{id}/access-reviews/{rid}/cancel` (`members.remove`).
#[utoipa::path(post, path = "/api/v1/teams/{id}/access-reviews/{rid}/cancel", tag = "teams",
    params(("id" = Uuid, Path), ("rid" = Uuid, Path)), responses((status = 200, body = AccessReview)))]
pub async fn cancel(
    State(state): State<AppState>,
    auth: Auth,
    Path((team_id, rid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<AccessReview>> {
    crate::authz::require(&state, team_id, auth.user_id(), "members.remove").await?;
    let n = sqlx::query(
        "UPDATE team_access_reviews SET status = 'cancelled', closed_by = $3, closed_at = now()
         WHERE id = $1 AND team_id = $2 AND status = 'open'",
    )
    .bind(rid)
    .bind(team_id)
    .bind(auth.user_id())
    .execute(&state.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(Error::conflict("This review is not open"));
    }
    audit::record(
        &state.db,
        audit::Entry::new(team_id, &auth, "access_review.cancelled")
            .details(serde_json::json!({ "review_id": rid })),
    )
    .await;
    Ok(Json(load(&state, team_id, rid).await?))
}

async fn notify_admins(state: &AppState, team_id: Uuid, subject: &str, text: &str) {
    let to: Vec<(String,)> = sqlx::query_as(
        "SELECT u.email FROM team_members m JOIN users u ON u.id = m.user_id
         WHERE m.team_id = $1 AND m.role IN ('owner', 'admin') LIMIT 20",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for (email,) in to {
        crate::users::notify(state, &email, subject, text).await;
    }
}

/// Hourly: open reviews that are due by policy, remind about overdue ones.
pub async fn run_scheduler(state: AppState) {
    crate::jobs::exclusive(state, "access-reviews", SCHEDULER_EVERY, |s| async move {
        scheduler_pass(&s).await
    })
    .await
}

/// One pass; returns how many reviews were opened or reminded about.
pub async fn scheduler_pass(state: &AppState) -> anyhow::Result<u64> {
    // Due: cadence on, nothing open, and the last review (or the team's birth)
    // is older than the cadence.
    let due: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT t.id, t.name FROM teams t JOIN team_policies p ON p.team_id = t.id
         WHERE p.access_review_days > 0
           AND NOT EXISTS (SELECT 1 FROM team_access_reviews r WHERE r.team_id = t.id AND r.status = 'open')
           AND coalesce((SELECT max(r.opened_at) FROM team_access_reviews r WHERE r.team_id = t.id), t.created_at)
               < now() - make_interval(days => p.access_review_days)",
    )
    .fetch_all(&state.db)
    .await?;
    let mut n = 0;
    for (team_id, name) in due {
        let Some(rid) = open_review(state, team_id, None)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        else {
            continue;
        };
        audit::record(
            &state.db,
            audit::Entry::system(team_id, "access_review.opened")
                .details(serde_json::json!({ "review_id": rid, "scheduled": true })),
        )
        .await;
        let url = format!(
            "{}/team/{team_id}/access-reviews/{rid}",
            state.cfg.public_url.trim_end_matches('/')
        );
        notify_admins(
            state,
            team_id,
            &format!("Access review due: {name}"),
            &format!(
                "It is time to confirm who still needs access to the team \"{name}\". \
                 Open the review, mark each member and vault access keep or remove, and complete it \
                 within {DUE_AFTER_DAYS} days.\n\n{url}"
            ),
        )
        .await;
        n += 1;
    }
    // Overdue reminders: once, 1 day after due_at (the flag is a closed_at-free marker in kept = -1).
    let overdue: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "UPDATE team_access_reviews r SET kept = -1
         FROM teams t
         WHERE t.id = r.team_id AND r.status = 'open' AND r.kept = 0 AND r.due_at < now()
         RETURNING r.id, r.team_id, t.name",
    )
    .fetch_all(&state.db)
    .await?;
    for (rid, team_id, name) in overdue {
        let url = format!(
            "{}/team/{team_id}/access-reviews/{rid}",
            state.cfg.public_url.trim_end_matches('/')
        );
        notify_admins(
            state,
            team_id,
            &format!("Access review overdue: {name}"),
            &format!(
                "The access review for the team \"{name}\" is past due and still has undecided lines.\n\n{url}"
            ),
        )
        .await;
        n += 1;
    }
    Ok(n)
}
