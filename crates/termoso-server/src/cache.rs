//! Redis: short-lived state (login handshakes, MFA/approval tokens, codes),
//! session cache, rate limits and cross-instance event fan-out.
//!
//! `TERMOSO_REDIS_URL` accepts `redis://`, `rediss://` (TLS) and
//! `redis+sentinel://[:password@]host1:26379,host2:26379/<master>[?db=0&sentinel_password=…]`.
//! With Sentinel the current master is resolved at start and re-checked every
//! 10 s; after a failover the connection is swapped without a restart.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::ApiResult;

#[derive(Clone)]
pub struct Cache {
    live: Arc<RwLock<Live>>,
    prefix: String,
}

struct Live {
    conn: ConnectionManager,
    client: redis::Client,
}

/// Parsed `redis+sentinel://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentinelUrl {
    pub sentinels: Vec<(String, u16)>,
    pub master: String,
    pub db: i64,
    pub password: Option<String>,
    pub sentinel_password: Option<String>,
    pub tls: bool,
}

impl SentinelUrl {
    pub fn parse(url: &str) -> anyhow::Result<Option<Self>> {
        let (tls, rest) = if let Some(r) = url.strip_prefix("redis+sentinel://") {
            (false, r)
        } else if let Some(r) = url.strip_prefix("rediss+sentinel://") {
            (true, r)
        } else {
            return Ok(None);
        };
        let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (hosts, master) = rest
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("sentinel URL needs /<master-name>"))?;
        let (userinfo, hosts) = match hosts.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, hosts),
        };
        let password = userinfo.and_then(|u| u.split_once(':').map(|(_, p)| p.to_string()));
        let mut sentinels = Vec::new();
        for h in hosts.split(',').filter(|h| !h.is_empty()) {
            let (host, port) = match h.rsplit_once(':') {
                Some((host, port)) if !host.contains(']') || host.ends_with(']') => {
                    (host.trim_matches(['[', ']']), port.parse::<u16>()?)
                }
                _ => (h, 26379),
            };
            sentinels.push((host.to_string(), port));
        }
        anyhow::ensure!(
            !sentinels.is_empty(),
            "sentinel URL needs at least one host"
        );
        anyhow::ensure!(!master.is_empty(), "sentinel URL needs /<master-name>");
        let mut db = 0;
        let mut sentinel_password = None;
        for kv in query.split('&').filter(|s| !s.is_empty()) {
            match kv.split_once('=') {
                Some(("db", v)) => db = v.parse()?,
                Some(("sentinel_password", v)) => sentinel_password = Some(v.to_string()),
                _ => {}
            }
        }
        Ok(Some(Self {
            sentinels,
            master: master.to_string(),
            db,
            password,
            sentinel_password,
            tls,
        }))
    }

    fn client(&self) -> anyhow::Result<redis::sentinel::SentinelClient> {
        use redis::sentinel::{SentinelClientBuilder, SentinelServerType};
        let addrs = self.sentinels.iter().map(|(h, p)| {
            if self.tls {
                redis::ConnectionAddr::TcpTls {
                    host: h.clone(),
                    port: *p,
                    insecure: false,
                    tls_params: None,
                }
            } else {
                redis::ConnectionAddr::Tcp(h.clone(), *p)
            }
        });
        let mut b = SentinelClientBuilder::new(addrs, &self.master, SentinelServerType::Master)?
            .set_client_to_redis_db(self.db);
        if self.tls {
            b = b.set_client_to_redis_tls_mode(redis::TlsMode::Secure);
        }
        if let Some(p) = &self.password {
            b = b.set_client_to_redis_password(p);
        }
        if let Some(p) = &self.sentinel_password {
            b = b.set_client_to_sentinel_password(p);
        }
        Ok(b.build()?)
    }
}

impl Cache {
    /// `prefix` namespaces every key and the event channel so several
    /// deployments can share one Redis.
    pub async fn connect(url: &str, prefix: &str) -> anyhow::Result<Self> {
        let sentinel = SentinelUrl::parse(url)?;
        let client = match &sentinel {
            Some(s) => s.client()?.async_get_client().await?,
            None => redis::Client::open(url)?,
        };
        let conn = client.get_connection_manager().await?;
        let cache = Self {
            live: Arc::new(RwLock::new(Live { conn, client })),
            prefix: prefix.to_string(),
        };
        if let Some(s) = sentinel {
            tokio::spawn(cache.clone().follow_master(s));
        }
        Ok(cache)
    }

    /// Re-resolve the master through Sentinel; swap the connection when it
    /// moved. Pub/sub consumers reconnect through `client()` on their own.
    async fn follow_master(self, s: SentinelUrl) {
        let mut sentinel = match s.client() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "sentinel client");
                return;
            }
        };
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let client = match sentinel.async_get_client().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "sentinel: master lookup failed");
                    continue;
                }
            };
            let current = self
                .live
                .read()
                .unwrap()
                .client
                .get_connection_info()
                .addr()
                .clone();
            if *client.get_connection_info().addr() == current {
                continue;
            }
            match client.get_connection_manager().await {
                Ok(conn) => {
                    tracing::warn!(from = %current, to = %client.get_connection_info().addr(), "redis master changed (sentinel failover)");
                    *self.live.write().unwrap() = Live { conn, client };
                }
                Err(e) => tracing::warn!(error = %e, "sentinel: connecting to new master failed"),
            }
        }
    }

    fn conn(&self) -> ConnectionManager {
        self.live.read().unwrap().conn.clone()
    }

    /// Client for the current master (pub/sub subscribers).
    pub fn client(&self) -> redis::Client {
        self.live.read().unwrap().client.clone()
    }

    pub fn events_channel(&self) -> String {
        format!("{}events", self.prefix)
    }

    /// Channel carrying multiplayer relay frames between instances.
    pub fn live_channel(&self) -> String {
        format!("{}live", self.prefix)
    }

    pub fn gateway_channel(&self) -> String {
        format!("{}gateway", self.prefix)
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        let mut c = self.conn();
        let _: String = redis::cmd("PING").query_async(&mut c).await?;
        Ok(())
    }

    pub async fn set_json<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl: Duration,
    ) -> ApiResult<()> {
        let mut c = self.conn();
        let body = serde_json::to_vec(value)?;
        let _: () = c.set_ex(self.key(key), body, ttl.as_secs().max(1)).await?;
        Ok(())
    }

    pub async fn get_json<T: DeserializeOwned>(&self, key: &str) -> ApiResult<Option<T>> {
        let mut c = self.conn();
        let raw: Option<Vec<u8>> = c.get(self.key(key)).await?;
        Ok(match raw {
            Some(b) => Some(serde_json::from_slice(&b)?),
            None => None,
        })
    }

    /// Atomically read and delete (single-use tokens).
    pub async fn take_json<T: DeserializeOwned>(&self, key: &str) -> ApiResult<Option<T>> {
        let mut c = self.conn();
        let raw: Option<Vec<u8>> = redis::cmd("GETDEL")
            .arg(self.key(key))
            .query_async(&mut c)
            .await?;
        Ok(match raw {
            Some(b) => Some(serde_json::from_slice(&b)?),
            None => None,
        })
    }

    pub async fn del(&self, key: &str) -> ApiResult<()> {
        let mut c = self.conn();
        let _: () = c.del(self.key(key)).await?;
        Ok(())
    }

    /// Current value of a counter created by [`Self::incr_window`] (0 when absent).
    pub async fn counter(&self, key: &str) -> ApiResult<u64> {
        let mut c = self.conn();
        let v: Option<u64> = c.get(self.key(key)).await?;
        Ok(v.unwrap_or(0))
    }

    /// Undo one [`Self::incr_window`] step (e.g. a quota slot the caller
    /// could not use). Never goes below zero.
    pub async fn decr(&self, key: &str) -> ApiResult<()> {
        let mut c = self.conn();
        let key = self.key(key);
        let v: i64 = c.decr(&key, 1i64).await?;
        if v < 0 {
            let _: () = c.del(&key).await?;
        }
        Ok(())
    }

    /// Fixed-window counter. Returns the new count and remaining TTL.
    pub async fn incr_window(&self, key: &str, window: Duration) -> ApiResult<(u64, u64)> {
        let mut c = self.conn();
        let key = self.key(key);
        let (count, ttl): (u64, i64) = redis::pipe()
            .atomic()
            .incr(&key, 1u64)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(window.as_secs().max(1))
            .arg("NX")
            .ignore()
            .ttl(&key)
            .query_async(&mut c)
            .await?;
        Ok((count, ttl.max(0) as u64))
    }

    pub async fn publish<T: Serialize>(&self, event: &T) -> ApiResult<()> {
        let mut c = self.conn();
        let body = serde_json::to_vec(event)?;
        let _: () = c.publish(self.events_channel(), body).await?;
        Ok(())
    }

    /// Publish an opaque frame on the multiplayer channel.
    pub async fn publish_live(&self, frame: Vec<u8>) -> ApiResult<()> {
        let mut c = self.conn();
        let _: () = c.publish(self.live_channel(), frame).await?;
        Ok(())
    }

    pub async fn publish_gateway(&self, frame: Vec<u8>) -> ApiResult<()> {
        let mut c = self.conn();
        let _: () = c.publish(self.gateway_channel(), frame).await?;
        Ok(())
    }

    /// Set one hash field and refresh the hash TTL; `true` when the field
    /// did not exist before.
    pub async fn hset_json<T: Serialize>(
        &self,
        key: &str,
        field: &str,
        value: &T,
        ttl: Duration,
    ) -> ApiResult<bool> {
        let mut c = self.conn();
        let body = serde_json::to_vec(value)?;
        let k = self.key(key);
        let (added,): (i64,) = redis::pipe()
            .hset(&k, field, body)
            .expire(&k, ttl.as_secs().max(1) as i64)
            .ignore()
            .query_async(&mut c)
            .await?;
        Ok(added > 0)
    }

    pub async fn hget_json<T: DeserializeOwned>(
        &self,
        key: &str,
        field: &str,
    ) -> ApiResult<Option<T>> {
        let mut c = self.conn();
        let raw: Option<Vec<u8>> = c.hget(self.key(key), field).await?;
        Ok(match raw {
            Some(b) => Some(serde_json::from_slice(&b)?),
            None => None,
        })
    }

    /// Remove one hash field; `true` when it existed.
    pub async fn hdel(&self, key: &str, field: &str) -> ApiResult<bool> {
        let mut c = self.conn();
        let n: i64 = c.hdel(self.key(key), field).await?;
        Ok(n > 0)
    }

    pub async fn hgetall_json<T: DeserializeOwned>(&self, key: &str) -> ApiResult<Vec<T>> {
        let mut c = self.conn();
        let raw: Vec<(String, Vec<u8>)> = c.hgetall(self.key(key)).await?;
        raw.into_iter()
            .map(|(_, b)| serde_json::from_slice(&b).map_err(Into::into))
            .collect()
    }
}
