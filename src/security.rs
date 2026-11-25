use crate::error::AppError;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use url::{Host, Url};
use zeroize::Zeroizing;

/// Wrapper for sensitive session cookies that zeroes memory on drop and redacts all formatting.
#[derive(Clone)]
pub struct SecretCookie(Zeroizing<String>);

impl SecretCookie {
    /// Constructs a validated session cookie value, rejecting header-injection control bytes.
    pub fn try_new(raw: &str) -> Result<Self, AppError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(AppError::AuthRequired(
                "session cookie must not be empty".to_string(),
            ));
        }
        if trimmed
            .bytes()
            .any(|b| b < 0x21 || b == 0x7f || b == b';' || !b.is_ascii())
        {
            return Err(AppError::AuthRequired(
                "session cookie contains disallowed control, delimiter, or non-ASCII characters"
                    .to_string(),
            ));
        }
        Ok(Self(Zeroizing::new(trimmed.to_string())))
    }

    /// Formats the cookie safely for the `Cookie` HTTP header against verified Substack hosts.
    pub fn format_header(&self, cookie_name: &str) -> Result<String, AppError> {
        validate_cookie_name(cookie_name)?;
        Ok(format!("{cookie_name}={}", self.0.as_str()))
    }
}

impl fmt::Debug for SecretCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretCookie([REDACTED])")
    }
}

impl fmt::Display for SecretCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Validates an HTTP session cookie name (`substack.sid` or `connect.sid`).
pub fn validate_cookie_name(name: &str) -> Result<&str, AppError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(AppError::InvalidConfig(
            "cookie name must match [a-zA-Z0-9._-]".to_string(),
        ));
    }
    Ok(name)
}

/// Validates a Substack publication subdomain as a single strict DNS label (`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).
///
/// Rejects dots, slashes, userinfo (`@`), uppercase, unicode homoglyphs, IP literals, and whitespace
/// to eliminate SSRF via subdomain substitution.
pub fn validate_subdomain(raw: &str) -> Result<String, AppError> {
    if raw.is_empty() || raw.len() > 63 {
        return Err(AppError::InvalidSubdomain(
            "subdomain must be 1..=63 ASCII characters".to_string(),
        ));
    }
    let bytes = raw.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(AppError::InvalidSubdomain(
            "subdomain must start with [a-z0-9]".to_string(),
        ));
    }
    let last = bytes[bytes.len() - 1];
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return Err(AppError::InvalidSubdomain(
            "subdomain must end with [a-z0-9]".to_string(),
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(AppError::InvalidSubdomain(
            "subdomain may only contain lowercase ASCII [a-z0-9-]".to_string(),
        ));
    }
    // Reject all-numeric labels so IP-style integers cannot masquerade as labels.
    if bytes.iter().all(u8::is_ascii_digit) {
        return Err(AppError::InvalidSubdomain(
            "numeric-only subdomains are disallowed".to_string(),
        ));
    }
    Ok(raw.to_string())
}

/// Validates a Substack draft or post ID (`^[a-zA-Z0-9_-]{1,128}$`).
pub fn validate_resource_id(raw: &str) -> Result<String, AppError> {
    if raw.is_empty() || raw.len() > 128 {
        return Err(AppError::InvalidIdentifier(
            "resource id must be 1..=128 characters".to_string(),
        ));
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(AppError::InvalidIdentifier(
            "resource id may only contain [a-zA-Z0-9_-]".to_string(),
        ));
    }
    Ok(raw.to_string())
}

/// Sanitizes Markdown hyperlinks and image sources, permitting only `https://`, `http://`,
/// `mailto:`, fragment references (`#...`), or single-slash relative paths (`/path`).
pub fn validate_safe_link(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 {
        return Err(AppError::InvalidUrl(
            "URL must be 1..=4096 bytes".to_string(),
        ));
    }
    if trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(AppError::InvalidUrl(
            "URL contains control characters".to_string(),
        ));
    }
    if trimmed.starts_with('#') {
        return Ok(trimmed.to_string());
    }
    if trimmed.starts_with('/') {
        if trimmed.starts_with("//") || trimmed.starts_with("/\\") {
            return Err(AppError::InvalidUrl(
                "protocol-relative URLs are blocked".to_string(),
            ));
        }
        return Ok(trimmed.to_string());
    }

    let parsed = Url::parse(trimmed).map_err(|e| AppError::InvalidUrl(e.to_string()))?;
    match parsed.scheme() {
        "https" | "http" => {
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(AppError::InvalidUrl(
                    "URL embedded credentials are blocked".to_string(),
                ));
            }
            if parsed.host_str().is_none() {
                return Err(AppError::InvalidUrl("URL missing host".to_string()));
            }
            Ok(parsed.to_string())
        }
        "mailto" => Ok(parsed.to_string()),
        other => Err(AppError::InvalidUrl(format!(
            "disallowed URL scheme `{other}`"
        ))),
    }
}

/// Enforces that an external inference server (`TurboFieldfareServer`) is strictly loopback-bound.
pub fn validate_loopback_endpoint(raw: &str) -> Result<Url, AppError> {
    let trimmed = raw.trim();
    let parsed = Url::parse(trimmed).map_err(|e| AppError::InvalidUrl(e.to_string()))?;
    if parsed.scheme() != "http" {
        return Err(AppError::SsrfBlocked(
            "TurboFieldfare local endpoint must use http:// on loopback".to_string(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::SsrfBlocked(
            "loopback endpoint must not contain credentials".to_string(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(AppError::SsrfBlocked(
            "loopback endpoint must not include query or fragment".to_string(),
        ));
    }
    let is_loopback = match parsed.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if !is_loopback {
        return Err(AppError::SsrfBlocked(format!(
            "refusing non-loopback inference host `{}`",
            parsed.host_str().unwrap_or("<none>")
        )));
    }
    Ok(parsed)
}

/// Validates a single relative filename entry inside `.gturbo` manifests (blocks traversal & hidden segments).
pub fn validate_safe_manifest_filename(name: &str) -> Result<(), AppError> {
    if name.is_empty() || name.len() > 255 {
        return Err(AppError::PathTraversal(
            "manifest filename length out of bounds".to_string(),
        ));
    }
    if name == "."
        || name == ".."
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.contains("..")
    {
        return Err(AppError::PathTraversal(format!(
            "unsafe manifest entry name `{name}`"
        )));
    }
    Ok(())
}

/// Length-hiding, constant-time comparison for `Authorization: Bearer <token>`.
pub fn constant_time_bearer_eq(
    auth_header: Option<&str>,
    expected_token: &Zeroizing<String>,
) -> bool {
    let Some(raw) = auth_header else {
        return false;
    };
    let supplied = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .unwrap_or("");
    if supplied.is_empty() || expected_token.is_empty() {
        return false;
    }
    let supplied_digest = Sha256::digest(supplied.as_bytes());
    let expected_digest = Sha256::digest(expected_token.as_bytes());
    supplied_digest.ct_eq(&expected_digest).into()
}

/// Guards HTTP endpoints against DNS rebinding via strict `Host` header validation.
pub fn validate_host_header(host: Option<&str>, allow_non_loopback: bool) -> bool {
    let Some(raw) = host else {
        return false;
    };
    if raw.is_empty() || raw.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return false;
    }
    if allow_non_loopback {
        return !raw.contains('/') && !raw.contains('@');
    }
    // Accept `localhost[:port]`, `127.0.0.1[:port]`, `[::1][:port]`
    if let Some(rest) = raw.strip_prefix("[::1]") {
        return rest.is_empty()
            || rest
                .strip_prefix(':')
                .is_some_and(|p| p.parse::<u16>().is_ok());
    }
    let (hostname, port_opt) = match raw.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (raw, None),
    };
    if let Some(p) = port_opt
        && p.parse::<u16>().is_err()
    {
        return false;
    }
    hostname.eq_ignore_ascii_case("localhost") || hostname == "127.0.0.1"
}

/// Guards HTTP/SSE endpoints against Cross-Site WebSocket/SSE Hijacking via `Origin` inspection.
pub fn validate_origin_header(origin: Option<&str>, allow_non_loopback: bool) -> bool {
    let Some(raw) = origin else {
        // Non-browser MCP clients (stdio bridges, CLI agents, curl) omit Origin.
        return true;
    };
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    let Ok(parsed) = Url::parse(raw) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    if allow_non_loopback {
        return parsed.host().is_some();
    }
    match parsed.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}
