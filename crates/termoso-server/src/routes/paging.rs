//! `offset` / `limit` for list endpoints.
//!
//! Without `limit` a list comes back whole (capped as before), so clients
//! released before paging keep working; with it the response also carries
//! the matching `total` so a cabinet can draw page controls.

use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub struct PageQuery {
    /// Rows to skip.
    #[serde(default)]
    pub offset: i64,
    /// Rows per page; omit for the whole list.
    pub limit: Option<i64>,
}

impl PageQuery {
    pub fn new(offset: i64, limit: Option<i64>) -> Self {
        Self { offset, limit }
    }

    /// `(offset, limit)` to bind; `max` caps both the page and the full list.
    pub fn window(&self, max: i64) -> (i64, i64) {
        (
            self.offset.max(0),
            self.limit.map_or(max, |l| l.clamp(1, max)),
        )
    }

    /// `total` for the response: the count query runs only when the caller
    /// actually pages; a whole list knows its own size.
    pub async fn total(
        &self,
        got: usize,
        db: &PgPool,
        count_sql: &'static str,
        id: Uuid,
    ) -> sqlx::Result<i64> {
        if self.limit.is_none() {
            return Ok(self.offset.max(0) + got as i64);
        }
        let (n,): (i64,) = sqlx::query_as(count_sql).bind(id).fetch_one(db).await?;
        Ok(n)
    }
}
