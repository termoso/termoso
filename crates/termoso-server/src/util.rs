//! Small helpers: tokens, codes, hashing, email normalisation.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{RngExt, distr::Uniform};

/// 32 random bytes as URL-safe base64 (43 chars).
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// Numeric code of `n` digits (email verification / device approval).
pub fn numeric_code(n: usize) -> String {
    let mut rng = rand::rng();
    let dist = Uniform::new_inclusive(0u8, 9).expect("valid range");
    (0..n)
        .map(|_| char::from(b'0' + rng.sample(dist)))
        .collect()
}

/// Backup code: 10 chars from an unambiguous alphabet, formatted `xxxxx-xxxxx`.
pub fn backup_code() -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::rng();
    let dist = Uniform::new(0, ALPHABET.len()).expect("valid range");
    let raw: String = (0..10)
        .map(|_| char::from(ALPHABET[rng.sample(dist)]))
        .collect();
    format!("{}-{}", &raw[..5], &raw[5..])
}

/// Keyed-less BLAKE3 hash, hex. Used for tokens (high entropy) – not passwords.
pub fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// Normalise backup / email codes before hashing (case, dashes, spaces).
pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

pub fn normalize_email(email: &str) -> Option<String> {
    let e = email.trim().to_lowercase();
    let (local, domain) = e.split_once('@')?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') || e.len() > 254 {
        return None;
    }
    if e.chars()
        .any(|c| c.is_whitespace() || c == '<' || c == '>' || c == ',')
    {
        return None;
    }
    Some(e)
}

/// `ivan@example.com` → `i***@example.com`
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().map(String::from).unwrap_or_default();
            format!("{first}***@{domain}")
        }
        None => "***".into(),
    }
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalisation() {
        assert_eq!(
            normalize_email("  Ivan@Example.COM ").unwrap(),
            "ivan@example.com"
        );
        assert!(normalize_email("nope").is_none());
        assert!(normalize_email("a@b").is_none());
        assert!(normalize_email("a b@c.d").is_none());
    }

    #[test]
    fn codes() {
        assert_eq!(numeric_code(6).len(), 6);
        assert!(numeric_code(6).chars().all(|c| c.is_ascii_digit()));
        let bc = backup_code();
        assert_eq!(bc.len(), 11);
        assert_eq!(normalize_code(&bc).len(), 10);
        assert_eq!(normalize_code(" AB-cd 12 "), "abcd12");
        assert_eq!(mask_email("ivan@example.com"), "i***@example.com");
    }
}
