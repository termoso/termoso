//! Discover machines at cloud providers (AWS EC2 / Lightsail, DigitalOcean,
//! Azure) so they can be imported as hosts, Termius "cloud integration"
//! style.
//!
//! This module only *reads*: it turns a set of provider credentials into a
//! list of [`CloudInstance`]s. Where the credentials live, how they are
//! encrypted and how instances become hosts is up to the shell. Nothing is
//! cached here and no request goes anywhere except the provider's own API
//! (overridable through [`Endpoints`] for tests and mocks).
//!
//! Credentials are held in [`zeroize`]d strings and are never part of an
//! error message or a log line; provider error *codes* are mapped to
//! [`CloudError`] so the UI can tell "wrong key" from "no network".

mod aws;
mod azure;
mod digitalocean;
pub(crate) mod sigv4;
pub(crate) mod xml;

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Which provider a configuration targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    /// Amazon Web Services (EC2 or Lightsail).
    Aws,
    /// DigitalOcean droplets.
    DigitalOcean,
    /// Microsoft Azure virtual machines.
    Azure,
}

impl CloudProvider {
    /// Human name.
    pub fn name(self) -> &'static str {
        match self {
            CloudProvider::Aws => "Amazon AWS",
            CloudProvider::DigitalOcean => "DigitalOcean",
            CloudProvider::Azure => "Microsoft Azure",
        }
    }

    /// Value stored in `Host::cloud_instance_type` (Termius-compatible).
    pub fn instance_type(self) -> &'static str {
        match self {
            CloudProvider::Aws => "Amazon AWS",
            CloudProvider::DigitalOcean => "DigitalOcean",
            CloudProvider::Azure => "azure",
        }
    }
}

/// AWS API family to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsService {
    /// Elastic Compute Cloud.
    #[default]
    Ec2,
    /// Lightsail instances.
    Lightsail,
}

/// Which address of an instance becomes the host address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressType {
    /// Public IP (default).
    #[default]
    Public,
    /// Private / VPC IP.
    Private,
}

/// AWS access key credentials scoped to one region.
#[derive(Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    /// Region code (`eu-central-1`).
    pub region: String,
    /// Access key id (`AKIA…`); not secret.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: Zeroizing<String>,
    /// EC2 or Lightsail.
    #[serde(default)]
    pub service: AwsService,
    /// Public or private address.
    #[serde(default)]
    pub address_type: AddressType,
}

/// DigitalOcean personal access token.
#[derive(Clone, Serialize, Deserialize)]
pub struct DigitalOceanConfig {
    /// API token (read scope is enough).
    pub token: Zeroizing<String>,
}

/// Azure service principal (client credentials flow).
#[derive(Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    /// Directory (tenant) id.
    pub tenant_id: String,
    /// Application (client) id.
    pub client_id: String,
    /// Client secret.
    pub client_secret: Zeroizing<String>,
}

/// Everything needed to list one provider account.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum CloudConfig {
    /// AWS.
    Aws(AwsConfig),
    /// DigitalOcean.
    DigitalOcean(DigitalOceanConfig),
    /// Azure.
    Azure(AzureConfig),
}

impl CloudConfig {
    /// Provider of this configuration.
    pub fn provider(&self) -> CloudProvider {
        match self {
            CloudConfig::Aws(_) => CloudProvider::Aws,
            CloudConfig::DigitalOcean(_) => CloudProvider::DigitalOcean,
            CloudConfig::Azure(_) => CloudProvider::Azure,
        }
    }

    /// Reject configurations that cannot possibly work before going online.
    pub fn validate(&self) -> Result<(), CloudError> {
        match self {
            CloudConfig::Aws(a) => {
                if a.region.trim().is_empty() {
                    return Err(CloudError::Invalid("region is required".into()));
                }
                if !a
                    .region
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
                {
                    return Err(CloudError::Invalid("region looks malformed".into()));
                }
                if a.access_key_id.trim().is_empty() || a.secret_access_key.trim().is_empty() {
                    return Err(CloudError::Invalid(
                        "access key id and secret access key are required".into(),
                    ));
                }
            }
            CloudConfig::DigitalOcean(d) => {
                if d.token.trim().is_empty() {
                    return Err(CloudError::Invalid("token is required".into()));
                }
            }
            CloudConfig::Azure(z) => {
                if z.tenant_id.trim().is_empty()
                    || z.client_id.trim().is_empty()
                    || z.client_secret.trim().is_empty()
                {
                    return Err(CloudError::Invalid(
                        "tenant id, client id and client secret are required".into(),
                    ));
                }
                if !z
                    .tenant_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                {
                    return Err(CloudError::Invalid("tenant id looks malformed".into()));
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for CloudConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudConfig::Aws(a) => f
                .debug_struct("Aws")
                .field("region", &a.region)
                .field("access_key_id", &a.access_key_id)
                .field("service", &a.service)
                .field("address_type", &a.address_type)
                .finish_non_exhaustive(),
            CloudConfig::DigitalOcean(_) => f.write_str("DigitalOcean { .. }"),
            CloudConfig::Azure(z) => f
                .debug_struct("Azure")
                .field("tenant_id", &z.tenant_id)
                .field("client_id", &z.client_id)
                .finish_non_exhaustive(),
        }
    }
}

/// A machine as seen at the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudInstance {
    /// Provider-unique id (`i-0abc…`, droplet id, Azure resource id).
    pub instance_id: String,
    /// Display name (tag `Name`, droplet name, VM name); falls back to the id.
    pub label: String,
    /// Address to connect to; `None` when the instance has no address of the
    /// requested type (stopped EC2 instance, VM without a public IP).
    pub address: Option<String>,
    /// Provider state (`running`, `active`, `PowerState/running`…).
    pub state: Option<String>,
    /// Region / zone / location.
    pub region: Option<String>,
    /// Size (`t3.micro`, `s-1vcpu-1gb`, `Standard_B1s`).
    pub size: Option<String>,
    /// Raw OS / image description from the provider.
    pub os: Option<String>,
    /// OS identifier from [`crate::osdetect::KNOWN`], guessed from `os`.
    pub os_name: Option<String>,
}

impl CloudInstance {
    fn finish(mut self) -> Self {
        if self.label.trim().is_empty() {
            self.label = self.instance_id.clone();
        }
        if self.os_name.is_none() {
            self.os_name = self
                .os
                .as_deref()
                .and_then(crate::osdetect::classify)
                .map(str::to_string);
        }
        self
    }
}

/// Why a discovery failed. `Display` is safe to show to the user.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum CloudError {
    /// Configuration is incomplete or malformed (checked offline).
    #[error("{0}")]
    Invalid(String),
    /// The provider rejected the credentials.
    #[error("{0}")]
    InvalidCredentials(String),
    /// Credentials are valid but lack permission for the listing call.
    #[error("{0}")]
    Forbidden(String),
    /// Provider throttled us.
    #[error("{0}")]
    RateLimited(String),
    /// Could not reach the provider (DNS, TLS, timeout, 5xx).
    #[error("{0}")]
    Unavailable(String),
    /// The provider answered something we do not understand.
    #[error("{0}")]
    Malformed(String),
}

impl CloudError {
    /// Stable machine-readable kind.
    pub fn kind(&self) -> &'static str {
        match self {
            CloudError::Invalid(_) => "invalid",
            CloudError::InvalidCredentials(_) => "cloud_invalid_credentials",
            CloudError::Forbidden(_) => "cloud_forbidden",
            CloudError::RateLimited(_) => "rate_limited",
            CloudError::Unavailable(_) => "cloud_unavailable",
            CloudError::Malformed(_) => "cloud_malformed",
        }
    }
}

impl From<reqwest::Error> for CloudError {
    fn from(e: reqwest::Error) -> Self {
        // `reqwest::Error`'s Display includes the URL, which carries no
        // secret for any of the providers here (credentials travel in
        // headers / bodies).
        if e.is_timeout() {
            CloudError::Unavailable("the provider did not answer in time".into())
        } else if e.is_connect() {
            CloudError::Unavailable(format!("could not connect: {}", strip_url(&e)))
        } else if e.is_decode() {
            CloudError::Malformed(format!("unreadable response: {}", strip_url(&e)))
        } else {
            CloudError::Unavailable(strip_url(&e))
        }
    }
}

/// `reqwest` prefixes messages with `error sending request for url (…)`;
/// keep only the cause.
fn strip_url(e: &reqwest::Error) -> String {
    let s = e.to_string();
    match s.split_once("): ") {
        Some((_, rest)) if s.starts_with("error sending request") => rest.to_string(),
        _ => s,
    }
}

/// Base URLs, overridable for tests, mocks and private endpoints
/// (GovCloud, Azure Stack). `None` = the public endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Endpoints {
    /// EC2 Query API base; `{region}` is substituted.
    /// Default `https://ec2.{region}.amazonaws.com`.
    #[serde(default)]
    pub aws_ec2: Option<String>,
    /// Lightsail JSON API base; `{region}` is substituted.
    /// Default `https://lightsail.{region}.amazonaws.com`.
    #[serde(default)]
    pub aws_lightsail: Option<String>,
    /// DigitalOcean API base. Default `https://api.digitalocean.com`.
    #[serde(default)]
    pub digitalocean: Option<String>,
    /// Azure AD token issuer. Default `https://login.microsoftonline.com`.
    #[serde(default)]
    pub azure_login: Option<String>,
    /// Azure Resource Manager. Default `https://management.azure.com`.
    #[serde(default)]
    pub azure_management: Option<String>,
}

impl Endpoints {
    fn aws_ec2(&self, region: &str) -> String {
        self.aws_ec2
            .as_deref()
            .unwrap_or("https://ec2.{region}.amazonaws.com")
            .replace("{region}", region)
    }

    fn aws_lightsail(&self, region: &str) -> String {
        self.aws_lightsail
            .as_deref()
            .unwrap_or("https://lightsail.{region}.amazonaws.com")
            .replace("{region}", region)
    }

    fn digitalocean(&self) -> &str {
        self.digitalocean
            .as_deref()
            .unwrap_or("https://api.digitalocean.com")
            .trim_end_matches('/')
    }

    fn azure_login(&self) -> &str {
        self.azure_login
            .as_deref()
            .unwrap_or("https://login.microsoftonline.com")
            .trim_end_matches('/')
    }

    fn azure_management(&self) -> &str {
        self.azure_management
            .as_deref()
            .unwrap_or("https://management.azure.com")
            .trim_end_matches('/')
    }
}

/// Provider client. Cheap to clone; holds no credentials.
#[derive(Debug, Clone)]
pub struct CloudClient {
    http: reqwest::Client,
    endpoints: Endpoints,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(45);

impl Default for CloudClient {
    fn default() -> Self {
        Self::new(Endpoints::default())
    }
}

impl CloudClient {
    /// Client for the given endpoints.
    pub fn new(endpoints: Endpoints) -> Self {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .user_agent(crate::api::default_user_agent())
            .build()
            .expect("reqwest client");
        Self { http, endpoints }
    }

    /// Endpoints in use.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// List every instance the credentials can see. Instances without an
    /// address of the requested type are included (with `address: None`) so
    /// the UI can explain why they are not importable.
    pub async fn discover(&self, config: &CloudConfig) -> Result<Vec<CloudInstance>, CloudError> {
        config.validate()?;
        let mut out = match config {
            CloudConfig::Aws(a) => match a.service {
                AwsService::Ec2 => aws::ec2_instances(&self.http, &self.endpoints, a).await?,
                AwsService::Lightsail => {
                    aws::lightsail_instances(&self.http, &self.endpoints, a).await?
                }
            },
            CloudConfig::DigitalOcean(d) => {
                digitalocean::droplets(&self.http, &self.endpoints, d).await?
            }
            CloudConfig::Azure(z) => {
                azure::virtual_machines(&self.http, &self.endpoints, z).await?
            }
        };
        out = out.into_iter().map(CloudInstance::finish).collect();
        out.sort_by(|a, b| {
            a.label
                .to_lowercase()
                .cmp(&b.label.to_lowercase())
                .then_with(|| a.instance_id.cmp(&b.instance_id))
        });
        out.dedup_by(|a, b| a.instance_id == b.instance_id);
        Ok(out)
    }
}

/// Map an HTTP status that is not provider-specific.
fn status_error(status: reqwest::StatusCode, body: &str) -> CloudError {
    let detail = trimmed(body);
    match status.as_u16() {
        401 => CloudError::InvalidCredentials(or(detail, "the provider rejected the credentials")),
        403 => CloudError::Forbidden(or(
            detail,
            "the credentials are not allowed to list instances",
        )),
        429 => CloudError::RateLimited(or(detail, "too many requests; try again in a minute")),
        500..=599 => CloudError::Unavailable(format!("provider error {}", status.as_u16())),
        _ => CloudError::Malformed(format!(
            "unexpected response {}{}",
            status.as_u16(),
            detail.map(|d| format!(": {d}")).unwrap_or_default()
        )),
    }
}

fn or(detail: Option<String>, fallback: &str) -> String {
    detail.unwrap_or_else(|| fallback.to_string())
}

/// First 300 chars of a body, single-line, or `None` when it is empty or
/// looks like markup (HTML error pages help nobody).
fn trimmed(body: &str) -> Option<String> {
    let t = body.trim();
    if t.is_empty() || t.starts_with('<') {
        return None;
    }
    let one_line: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
    Some(one_line.chars().take(300).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_debug_hides_secrets() {
        let c = CloudConfig::Aws(AwsConfig {
            region: "eu-west-1".into(),
            access_key_id: "AKIAEXAMPLE".into(),
            secret_access_key: Zeroizing::new("SUPERSECRET".into()),
            service: AwsService::Ec2,
            address_type: AddressType::Public,
        });
        let dbg = format!("{c:?}");
        assert!(dbg.contains("AKIAEXAMPLE"));
        assert!(!dbg.contains("SUPERSECRET"));

        let d = CloudConfig::DigitalOcean(DigitalOceanConfig {
            token: Zeroizing::new("dop_v1_secret".into()),
        });
        assert!(!format!("{d:?}").contains("secret"));

        let z = CloudConfig::Azure(AzureConfig {
            tenant_id: "t".into(),
            client_id: "c".into(),
            client_secret: Zeroizing::new("shh".into()),
        });
        assert!(!format!("{z:?}").contains("shh"));
    }

    #[test]
    fn validate_catches_blanks() {
        let c = CloudConfig::Aws(AwsConfig {
            region: "".into(),
            access_key_id: "a".into(),
            secret_access_key: Zeroizing::new("b".into()),
            service: AwsService::Ec2,
            address_type: AddressType::Public,
        });
        assert!(matches!(c.validate(), Err(CloudError::Invalid(_))));
        let d = CloudConfig::DigitalOcean(DigitalOceanConfig {
            token: Zeroizing::new("  ".into()),
        });
        assert!(matches!(d.validate(), Err(CloudError::Invalid(_))));
        let z = CloudConfig::Azure(AzureConfig {
            tenant_id: "bad tenant".into(),
            client_id: "c".into(),
            client_secret: Zeroizing::new("s".into()),
        });
        assert!(matches!(z.validate(), Err(CloudError::Invalid(_))));
    }

    #[test]
    fn config_roundtrips_with_provider_tag() {
        let c = CloudConfig::DigitalOcean(DigitalOceanConfig {
            token: Zeroizing::new("tok".into()),
        });
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["provider"], "digital_ocean");
        let back: CloudConfig = serde_json::from_value(json).unwrap();
        assert_eq!(back.provider(), CloudProvider::DigitalOcean);
    }

    #[test]
    fn finish_fills_label_and_os() {
        let i = CloudInstance {
            instance_id: "i-1".into(),
            label: " ".into(),
            address: None,
            state: None,
            region: None,
            size: None,
            os: Some("Ubuntu 22.04 LTS".into()),
            os_name: None,
        }
        .finish();
        assert_eq!(i.label, "i-1");
        assert_eq!(i.os_name.as_deref(), Some("ubuntu"));
    }
}
