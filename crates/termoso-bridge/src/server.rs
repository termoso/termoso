//! Minimal client for the three server endpoints a bridge token may use.

use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use termoso_proto::bridge::BridgeSelf;
use termoso_proto::error::ApiError;
use termoso_proto::sync::{PullRequest, PullResponse, PushRequest, PushResponse};
use url::Url;
use uuid::Uuid;

use crate::error::{BridgeError, Result};

pub struct ServerClient {
    http: reqwest::Client,
    base: Url,
    token: String,
}

impl ServerClient {
    pub fn new(server: &str, token: String) -> Result<Self> {
        let mut base = Url::parse(server)
            .map_err(|e| BridgeError::Credentials(format!("bad server URL: {e}")))?;
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("termoso-bridge/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { http, base, token })
    }

    pub fn server_url(&self) -> &Url {
        &self.base
    }

    fn api_url(&self, path: &str) -> Url {
        self.base
            .join(&format!("api/v1/{}", path.trim_start_matches('/')))
            .expect("relative api path")
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<T> {
        let mut rb = self
            .http
            .request(method, self.api_url(path))
            .bearer_auth(&self.token);
        if let Some(b) = body {
            rb = rb.json(b);
        }
        let resp = rb.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(api_error(status, &text));
        }
        Ok(resp.json().await?)
    }

    /// `GET /bridge/me`.
    pub async fn me(&self) -> Result<BridgeSelf> {
        self.send::<BridgeSelf>(Method::GET, "bridge/me", None::<&()>)
            .await
    }

    /// `POST /sync/pull`.
    pub async fn pull(&self, req: &PullRequest) -> Result<PullResponse> {
        self.send(Method::POST, "sync/pull", Some(req)).await
    }

    /// `POST /teams/{id}/automations/runs/claim`.
    pub async fn claim_runs(
        &self,
        team_id: Uuid,
        req: &termoso_proto::automation::ClaimRunsRequest,
    ) -> Result<termoso_proto::automation::ClaimRunsResponse> {
        self.send(
            Method::POST,
            &format!("teams/{team_id}/automations/runs/claim"),
            Some(req),
        )
        .await
    }

    /// `PATCH /teams/{id}/automations/runs/{rid}`.
    pub async fn finish_run(
        &self,
        team_id: Uuid,
        run_id: Uuid,
        req: &termoso_proto::automation::FinishRunRequest,
    ) -> Result<termoso_proto::automation::AutomationRun> {
        self.send(
            Method::PATCH,
            &format!("teams/{team_id}/automations/runs/{run_id}"),
            Some(req),
        )
        .await
    }

    /// `POST /sync/push`.
    pub async fn push(&self, req: &PushRequest) -> Result<PushResponse> {
        self.send(Method::POST, "sync/push", Some(req)).await
    }
}

fn api_error(status: StatusCode, body: &str) -> BridgeError {
    match serde_json::from_str::<ApiError>(body) {
        Ok(e) => BridgeError::Server {
            status: status.as_u16(),
            code: e.code,
            message: e.message,
        },
        Err(_) => BridgeError::Server {
            status: status.as_u16(),
            code: "http_error".into(),
            message: status
                .canonical_reason()
                .unwrap_or("request failed")
                .to_string(),
        },
    }
}
