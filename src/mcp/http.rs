use crate::mcp::SubstackMcpServer;
use crate::security::{constant_time_bearer_eq, validate_host_header, validate_origin_header};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tokio_util::sync::CancellationToken;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CONCURRENT_REQUESTS: usize = 128;
pub const MAX_LEGACY_SSE_SESSIONS: usize = 64;
const SSE_CHANNEL_CAPACITY: usize = 64;

#[derive(Clone)]
pub struct HttpSecurityConfig {
    pub allow_non_loopback: bool,
    pub bearer_token: Option<Zeroizing<String>>,
    pub max_body_bytes: usize,
}

impl Default for HttpSecurityConfig {
    fn default() -> Self {
        Self {
            allow_non_loopback: false,
            bearer_token: None,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

#[derive(Clone)]
struct AppHttpState {
    server: SubstackMcpServer,
    security: HttpSecurityConfig,
    sse_sessions: Arc<Mutex<HashMap<String, mpsc::Sender<String>>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyMessageQuery {
    session_id: String,
}

/// Builds the hardened Axum router exposing:
/// - `/mcp` (MCP 2.0 Streamable HTTP + native SSE streaming)
/// - `/sse` + `/message` (legacy HTTP+SSE MCP transport)
/// - `/healthz` (unauthenticated health probe)
pub fn build_router(
    server: SubstackMcpServer,
    security: HttpSecurityConfig,
    ct: CancellationToken,
) -> Router {
    let mcp_backend = server.clone();
    let streamable_service = StreamableHttpService::new(
        move || Ok(mcp_backend.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_cancellation_token(ct),
    );

    let max_body = security.max_body_bytes;
    let state = AppHttpState {
        server,
        security,
        sse_sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/sse", get(legacy_sse_handler))
        .route("/message", post(legacy_message_handler))
        .nest_service("/mcp", streamable_service)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_guard_middleware,
        ))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'"),
        ))
        .with_state(state)
}

async fn security_guard_middleware(
    State(state): State<AppHttpState>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    if !validate_host_header(host, state.security.allow_non_loopback) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "blocked invalid Host header (DNS rebinding guard)" })),
        )
            .into_response();
    }

    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if !validate_origin_header(origin, state.security.allow_non_loopback) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "blocked cross-origin browser request" })),
        )
            .into_response();
    }

    if req.uri().path() != "/healthz"
        && let Some(ref expected) = state.security.bearer_token
    {
        let auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if !constant_time_bearer_eq(auth, expected) {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                Json(json!({ "error": "missing or invalid Bearer token" })),
            )
                .into_response();
        }
    }

    next.run(req).await
}

async fn healthz_handler(State(state): State<AppHttpState>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "protocol": "mcp-2.0+sse",
        "loopback_only": !state.security.allow_non_loopback,
    }))
}

struct SessionDropGuard {
    session_id: String,
    sessions: Arc<Mutex<HashMap<String, mpsc::Sender<String>>>>,
}

impl Drop for SessionDropGuard {
    fn drop(&mut self) {
        let id = self.session_id.clone();
        let sessions = self.sessions.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let mut map = sessions.lock().await;
                map.remove(&id);
            });
        }
    }
}

async fn legacy_sse_handler(State(state): State<AppHttpState>) -> Response {
    let session_id = Uuid::new_v4().to_string();
    let (tx, rx) = mpsc::channel::<String>(SSE_CHANNEL_CAPACITY);

    {
        let mut sessions = state.sse_sessions.lock().await;
        sessions.retain(|_, sender| !sender.is_closed());
        if sessions.len() >= MAX_LEGACY_SSE_SESSIONS {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "maximum concurrent SSE sessions reached" })),
            )
                .into_response();
        }
        sessions.insert(session_id.clone(), tx);
    }

    let endpoint_uri = format!("/message?sessionId={session_id}");
    let guard = SessionDropGuard {
        session_id,
        sessions: state.sse_sessions.clone(),
    };

    let stream = build_sse_stream(endpoint_uri, rx, guard);
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

fn build_sse_stream(
    endpoint_uri: String,
    rx: mpsc::Receiver<String>,
    guard: SessionDropGuard,
) -> impl Stream<Item = Result<Event, Infallible>> {
    use futures::StreamExt as _;
    let initial = tokio_stream::once(Ok(Event::default().event("endpoint").data(endpoint_uri)));
    let body = ReceiverStream::new(rx).map(move |payload| {
        let _keep_guard_alive = &guard;
        Ok(Event::default().event("message").data(payload))
    });
    initial.chain(body)
}

async fn legacy_message_handler(
    State(state): State<AppHttpState>,
    Query(q): Query<LegacyMessageQuery>,
    _headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let sender = {
        let sessions = state.sse_sessions.lock().await;
        sessions.get(&q.session_id).cloned()
    };
    let Some(tx) = sender else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "unknown or expired SSE sessionId" })),
        )
            .into_response();
    };

    if let Some(reply) = state.server.dispatch_legacy_jsonrpc(&payload).await {
        let Ok(encoded) = serde_json::to_string(&reply) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "failed to encode JSON-RPC response" })),
            )
                .into_response();
        };
        if tx.try_send(encoded).is_err() {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "SSE client backpressure or disconnected" })),
            )
                .into_response();
        }
    }

    (StatusCode::ACCEPTED, Json(json!({ "accepted": true }))).into_response()
}
