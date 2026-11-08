//! AWS Signature Version 4 ([`sign`] for the POST requests of the EC2 Query
//! and Lightsail APIs, [`sign_request`] for any method with a query string,
//! as S3 needs). Reference:
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Headers to add to the request, in order.
pub struct Signed {
    /// `Authorization` header value.
    pub authorization: String,
    /// `X-Amz-Date` header value.
    pub amz_date: String,
}

/// Inputs for one request.
pub struct Request<'a> {
    /// `ec2`, `lightsail`.
    pub service: &'a str,
    /// `eu-central-1`.
    pub region: &'a str,
    /// Host header (no scheme, includes port when non-default).
    pub host: &'a str,
    /// Request path (`/`).
    pub path: &'a str,
    /// Extra headers to sign (lowercase name → value), besides `host` and
    /// `x-amz-date`. Values must already be trimmed.
    pub headers: &'a [(&'a str, &'a str)],
    /// Request body bytes.
    pub body: &'a [u8],
}

/// Sign a POST request at `now`.
pub fn sign(req: &Request<'_>, access_key: &str, secret_key: &str, now: DateTime<Utc>) -> Signed {
    sign_request(
        &GenericRequest {
            method: "POST",
            service: req.service,
            region: req.region,
            host: req.host,
            path: req.path,
            query: "",
            headers: req.headers,
            payload_hash: &hex::encode(Sha256::digest(req.body)),
        },
        access_key,
        secret_key,
        now,
    )
}

/// Inputs for one request of any method.
pub struct GenericRequest<'a> {
    /// `GET`, `PUT`, …
    pub method: &'a str,
    /// `s3`, `ec2`.
    pub service: &'a str,
    /// `us-east-1`.
    pub region: &'a str,
    /// Host header (no scheme, includes port when non-default).
    pub host: &'a str,
    /// Request path, already URI-encoded the AWS way (`/` kept).
    pub path: &'a str,
    /// Canonical query string: `k=v` pairs sorted by name, AWS-encoded,
    /// joined with `&`; empty when there is none.
    pub query: &'a str,
    /// Extra headers to sign (name → trimmed value), besides `host` and
    /// `x-amz-date`.
    pub headers: &'a [(&'a str, &'a str)],
    /// Lowercase hex SHA-256 of the body (`UNSIGNED-PAYLOAD` for streams).
    pub payload_hash: &'a str,
}

/// Sign any request at `now`.
pub fn sign_request(
    req: &GenericRequest<'_>,
    access_key: &str,
    secret_key: &str,
    now: DateTime<Utc>,
) -> Signed {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();

    let mut headers: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    headers.push(("host".into(), req.host.to_string()));
    headers.push(("x-amz-date".into(), amz_date.clone()));
    headers.sort();

    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let payload_hash = req.payload_hash;

    let canonical_request = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        method = req.method,
        path = if req.path.is_empty() { "/" } else { req.path },
        query = req.query,
    );
    let scope = format!("{date}/{}/{}/aws4_request", req.region, req.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let k_date = hmac(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, req.region.as_bytes());
    let k_service = hmac(&k_region, req.service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

    Signed {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        ),
        amz_date,
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Vector from the AWS SigV4 test suite (`post-vanilla`), adapted to the
    /// fixed date the suite uses.
    #[test]
    fn matches_aws_test_suite_post_vanilla() {
        let now = Utc.with_ymd_and_hms(2015, 8, 30, 12, 36, 0).unwrap();
        let signed = sign(
            &Request {
                service: "service",
                region: "us-east-1",
                host: "example.amazonaws.com",
                path: "/",
                headers: &[],
                body: b"",
            },
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            now,
        );
        assert_eq!(signed.amz_date, "20150830T123600Z");
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
        );
    }

    #[test]
    fn extra_headers_are_sorted_and_signed() {
        let now = Utc.with_ymd_and_hms(2015, 8, 30, 12, 36, 0).unwrap();
        let signed = sign(
            &Request {
                service: "ec2",
                region: "eu-west-1",
                host: "ec2.eu-west-1.amazonaws.com",
                path: "/",
                headers: &[("Content-Type", "application/x-www-form-urlencoded")],
                body: b"Action=DescribeInstances&Version=2016-11-15",
            },
            "AKIDEXAMPLE",
            "secret",
            now,
        );
        assert!(
            signed
                .authorization
                .contains("SignedHeaders=content-type;host;x-amz-date")
        );
        assert!(!signed.authorization.contains("secret"));
    }
}
