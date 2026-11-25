use crate::editor::prosemirror::ProseMirrorDoc;
use crate::error::AppError;
use crate::security::{SecretCookie, validate_resource_id, validate_subdomain};
use reqwest::{Client, Method, redirect::Policy};
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SubstackResponse {
    pub dry_run: bool,
    pub endpoint: String,
    pub status: u16,
    pub body: Value,
}

#[derive(Clone)]
pub struct SubstackClient {
    http: Client,
    default_publication: Option<String>,
    cookie: Option<SecretCookie>,
    cookie_name: String,
    min_interval: Duration,
    last_request: Arc<Mutex<Option<Instant>>>,
    allow_publish: bool,
}

impl SubstackClient {
    /// Builds a hardened Substack HTTP client using pure `rustls`, zero redirects, and fixed rate limits.
    pub fn try_new(
        default_publication: Option<String>,
        cookie: Option<SecretCookie>,
        cookie_name: String,
        rate_limit_ms: u64,
        allow_publish: bool,
    ) -> Result<Self, AppError> {
        let validated_pub = default_publication
            .as_deref()
            .map(validate_subdomain)
            .transpose()?;

        let http = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent("substack-mcp-rs/0.1.0 (+https://github.com/8b-is/substack-mcp-rs)")
            .build()
            .map_err(|e| AppError::Http(e.to_string()))?;

        Ok(Self {
            http,
            default_publication: validated_pub,
            cookie,
            cookie_name,
            min_interval: Duration::from_millis(rate_limit_ms.max(250)),
            last_request: Arc::new(Mutex::new(None)),
            allow_publish,
        })
    }

    pub fn allow_publish(&self) -> bool {
        self.allow_publish
    }

    pub fn has_cookie(&self) -> bool {
        self.cookie.is_some()
    }

    fn resolve_publication(&self, pub_override: Option<&str>) -> Result<String, AppError> {
        match pub_override {
            Some(p) => validate_subdomain(p),
            None => self.default_publication.clone().ok_or_else(|| {
                AppError::InvalidSubdomain(
                    "no publication provided and no default publication configured".to_string(),
                )
            }),
        }
    }

    fn require_cookie(&self) -> Result<String, AppError> {
        let Some(ref cookie) = self.cookie else {
            return Err(AppError::AuthRequired(
                "SUBSTACK_SID cookie is not configured".to_string(),
            ));
        };
        cookie.format_header(&self.cookie_name)
    }

    async fn throttle(&self) {
        let mut guard = self.last_request.lock().await;
        if let Some(prev) = *guard
            && let Some(wait) = self.min_interval.checked_sub(prev.elapsed())
        {
            tokio::time::sleep(wait).await;
        }
        *guard = Some(Instant::now());
    }

    async fn send_json(
        &self,
        method: Method,
        url: &str,
        requires_auth: bool,
        payload: Option<Value>,
    ) -> Result<SubstackResponse, AppError> {
        self.throttle().await;
        let mut req = self.http.request(method, url);
        if requires_auth {
            let header_val = self.require_cookie()?;
            req = req.header(reqwest::header::COOKIE, header_val);
        }
        if let Some(body) = payload {
            req = req.json(&body);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| AppError::Http(e.to_string()))?;

        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AppError::Http(e.to_string()))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(AppError::PayloadTooLarge {
                max_bytes: MAX_RESPONSE_BYTES,
            });
        }
        if !status.is_success() {
            return Err(AppError::UpstreamHttp {
                status: status.as_u16(),
                message: format!("Substack endpoint `{url}` returned HTTP {status}"),
            });
        }
        let body: Value = if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&bytes)?
        };

        Ok(SubstackResponse {
            dry_run: false,
            endpoint: url.to_string(),
            status: status.as_u16(),
            body,
        })
    }

    pub async fn verify_session(&self) -> Result<SubstackResponse, AppError> {
        self.send_json(
            Method::GET,
            "https://substack.com/api/v1/user/profile/self",
            true,
            None,
        )
        .await
    }

    pub async fn list_drafts(
        &self,
        publication: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<SubstackResponse, AppError> {
        let sub = self.resolve_publication(publication)?;
        let capped_limit = limit.clamp(1, 50);
        let url = format!(
            "https://{sub}.substack.com/api/v1/drafts?limit={capped_limit}&offset={offset}"
        );
        self.send_json(Method::GET, &url, true, None).await
    }

    pub async fn get_draft(
        &self,
        publication: Option<&str>,
        draft_id: &str,
    ) -> Result<SubstackResponse, AppError> {
        let sub = self.resolve_publication(publication)?;
        let id = validate_resource_id(draft_id)?;
        let url = format!("https://{sub}.substack.com/api/v1/drafts/{id}");
        self.send_json(Method::GET, &url, true, None).await
    }

    pub async fn create_draft(
        &self,
        publication: Option<&str>,
        title: &str,
        subtitle: Option<&str>,
        doc: &ProseMirrorDoc,
        audience: &str,
        dry_run: bool,
    ) -> Result<SubstackResponse, AppError> {
        let sub = self.resolve_publication(publication)?;
        let url = format!("https://{sub}.substack.com/api/v1/drafts");
        let safe_audience = match audience {
            "only_paid" => "only_paid",
            _ => "everyone",
        };
        let body_json_str = serde_json::to_string(doc)?;
        let payload = json!({
            "draft_title": title,
            "draft_subtitle": subtitle.unwrap_or(""),
            "draft_body": body_json_str,
            "type": "newsletter",
            "audience": safe_audience,
        });
        if dry_run {
            return Ok(SubstackResponse {
                dry_run: true,
                endpoint: url,
                status: 0,
                body: payload,
            });
        }
        self.send_json(Method::POST, &url, true, Some(payload))
            .await
    }

    pub async fn update_draft(
        &self,
        publication: Option<&str>,
        draft_id: &str,
        title: &str,
        subtitle: Option<&str>,
        doc: &ProseMirrorDoc,
        dry_run: bool,
    ) -> Result<SubstackResponse, AppError> {
        let sub = self.resolve_publication(publication)?;
        let id = validate_resource_id(draft_id)?;
        let url = format!("https://{sub}.substack.com/api/v1/drafts/{id}");
        let body_json_str = serde_json::to_string(doc)?;
        let payload = json!({
            "draft_title": title,
            "draft_subtitle": subtitle.unwrap_or(""),
            "draft_body": body_json_str,
            "type": "newsletter",
        });
        if dry_run {
            return Ok(SubstackResponse {
                dry_run: true,
                endpoint: url,
                status: 0,
                body: payload,
            });
        }
        self.send_json(Method::PUT, &url, true, Some(payload)).await
    }

    /// Dual-gated draft publisher: fails unless `--allow-publish` was set at startup AND `confirm_publish == true`.
    pub async fn publish_draft(
        &self,
        publication: Option<&str>,
        draft_id: &str,
        send_email: bool,
        confirm_publish: bool,
    ) -> Result<SubstackResponse, AppError> {
        if !self.allow_publish {
            return Err(AppError::PublishLocked(
                "server started without --allow-publish safeguard override".to_string(),
            ));
        }
        if !confirm_publish {
            return Err(AppError::PublishLocked(
                "explicit per-call `confirm_publish: true` flag is required".to_string(),
            ));
        }
        let sub = self.resolve_publication(publication)?;
        let id = validate_resource_id(draft_id)?;
        let url = format!("https://{sub}.substack.com/api/v1/drafts/{id}/publish");
        let payload = json!({
            "send": send_email,
        });
        self.send_json(Method::POST, &url, true, Some(payload))
            .await
    }

    /// Reads public newsletter posts (requires no session cookie).
    pub async fn list_posts(
        &self,
        publication: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<SubstackResponse, AppError> {
        let sub = self.resolve_publication(publication)?;
        let capped_limit = limit.clamp(1, 50);
        let url = format!(
            "https://{sub}.substack.com/api/v1/archive?sort=new&limit={capped_limit}&offset={offset}"
        );
        self.send_json(Method::GET, &url, false, None).await
    }
}
