#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::http::StatusCode;
use futures::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use substack_mcp_rs::editor::SmallEditorModel;
use substack_mcp_rs::editor::prosemirror::{
    DEFAULT_MAX_MARKDOWN_BYTES, markdown_to_prosemirror, prosemirror_to_markdown,
};
use substack_mcp_rs::error::AppError;
use substack_mcp_rs::mcp::SubstackMcpServer;
use substack_mcp_rs::mcp::http::{HttpSecurityConfig, build_router};
use substack_mcp_rs::security::{
    SecretCookie, constant_time_bearer_eq, validate_host_header, validate_loopback_endpoint,
    validate_origin_header, validate_safe_link, validate_safe_manifest_filename,
    validate_subdomain,
};
use substack_mcp_rs::substack::SubstackClient;
use substack_mcp_rs::turbo_fieldfare::verify_gturbo_directory;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn spawn_test_server(
    allow_publish: bool,
    bearer: Option<&str>,
) -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
    let substack = Arc::new(
        SubstackClient::try_new(
            Some("testpub".to_string()),
            None,
            "substack.sid".to_string(),
            250,
            allow_publish,
        )
        .unwrap(),
    );
    let mcp = SubstackMcpServer::new(substack, None);
    let ct = CancellationToken::new();
    let cfg = HttpSecurityConfig {
        allow_non_loopback: false,
        bearer_token: bearer.map(|t| Zeroizing::new(t.to_string())),
        max_body_bytes: 2 * 1024 * 1024,
    };
    let router = build_router(mcp, cfg, ct.clone());
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(std_listener).unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, ct, handle)
}

#[test]
fn test_ssrf_subdomain_validation_blocks_attacks() {
    assert!(validate_subdomain("peterlodri").is_ok());
    assert!(validate_subdomain("my-pub-2026").is_ok());

    for bad in [
        "",
        "evil.com",
        "pub.substack.com",
        "pub@evil.com",
        "pub/../../etc",
        "127.0.0.1",
        "169.254.169.254",
        "123456",
        "-leading",
        "trailing-",
        "UpperCase",
        "bad host",
        "unicøde",
        &"a".repeat(64),
    ] {
        assert!(
            validate_subdomain(bad).is_err(),
            "subdomain `{bad}` should have been rejected"
        );
    }
}

#[test]
fn test_cookie_header_injection_and_secret_redaction() {
    let cookie = SecretCookie::try_new("s%3Asafe_session_token_value").unwrap();
    assert_eq!(format!("{cookie:?}"), "SecretCookie([REDACTED])");
    assert_eq!(format!("{cookie}"), "[REDACTED]");
    assert!(cookie.format_header("substack.sid").is_ok());

    for bad in [
        "",
        "val\r\nX-Evil: 1",
        "val\nInjected: 1",
        "val\0null",
        "val; Path=/",
        "val with space",
        "nönascii",
    ] {
        assert!(
            SecretCookie::try_new(bad).is_err(),
            "cookie `{bad}` must fail validation"
        );
    }
}

#[test]
fn test_safe_link_and_prosemirror_xss_neutralization() {
    assert!(validate_safe_link("https://substack.com/post/1").is_ok());
    assert!(validate_safe_link("/posts/part-1.html").is_ok());
    assert!(validate_safe_link("mailto:hello@example.org").is_ok());

    for bad in [
        "javascript:alert(1)",
        "JAVASCRIPT:alert(document.cookie)",
        "vbscript:msgbox(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "//evil.example/redirect",
        "https://user:pass@evil.example/",
    ] {
        assert!(
            validate_safe_link(bad).is_err(),
            "URL `{bad}` should have been blocked"
        );
    }

    let md = "# Security Title\n\nSafe [link](https://example.org) and [bad](javascript:alert(1)) plus ![x](file:///etc/shadow).\n\n<script>alert(2)</script>\n";
    let res = markdown_to_prosemirror(md, DEFAULT_MAX_MARKDOWN_BYTES).unwrap();
    let json_str = serde_json::to_string(&res.doc).unwrap();
    assert!(!json_str.contains("javascript:"));
    assert!(!json_str.contains("file:///etc/shadow"));
    assert!(!json_str.contains("<script>"));
    assert_eq!(res.link_count, 1);
    assert_eq!(res.stripped_unsafe_links.len(), 2);

    let roundtrip = prosemirror_to_markdown(&res.doc);
    assert!(roundtrip.contains("# Security Title"));
    assert!(roundtrip.contains("[link](https://example.org/)"));
}

#[test]
fn test_small_editor_model_lints_and_polish() {
    let input = "# Hardening Rust MCP\n\nIn today's fast-paced world, let's delve into why BTI is a game-changer.  \n\n```rust\n// delve into stays untouched inside code fence\nlet x = 1;\n```\n";
    let polished = SmallEditorModel::deterministic_polish(input).unwrap();
    assert!(polished.changes_applied >= 3);
    assert!(!polished.polished_markdown.contains("game-changer"));
    assert!(
        polished
            .polished_markdown
            .contains("// delve into stays untouched inside code fence")
    );
    assert_eq!(polished.after.suggested_slug, "hardening-rust-mcp");
}

#[test]
fn test_loopback_endpoint_ssrf_guard() {
    assert!(validate_loopback_endpoint("http://127.0.0.1:8080").is_ok());
    assert!(validate_loopback_endpoint("http://localhost:11434").is_ok());
    assert!(validate_loopback_endpoint("http://[::1]:8080").is_ok());

    for bad in [
        "https://127.0.0.1:8080",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5:8080",
        "http://192.168.1.10:8080",
        "http://attacker.example:8080",
        "http://user@127.0.0.1:8080",
        "http://127.0.0.1:8080?next=evil",
    ] {
        assert!(
            validate_loopback_endpoint(bad).is_err(),
            "non-loopback/unsafe inference URL `{bad}` must fail"
        );
    }
}

#[test]
fn test_gturbo_manifest_integrity_and_traversal_guards() {
    assert!(validate_safe_manifest_filename("weights-00001.bin").is_ok());
    for bad in [
        "../secret",
        "/etc/passwd",
        "sub/file.bin",
        ".hidden",
        "a\0b",
    ] {
        assert!(validate_safe_manifest_filename(bad).is_err());
    }

    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let weights_bytes = b"GTURBO_MOCK_SHARD_DATA_01";
    fs::write(root.join("shard0.bin"), weights_bytes).unwrap();
    let weights_sha = sha256_hex(weights_bytes);

    let manifest = json!({
        "magic": "GTURBO01",
        "versionMajor": 1,
        "versionMinor": 0,
        "flags": { "int4": true },
        "modelID": "gemma-4-26b-a4b-test",
        "files": {
            "shard0.bin": { "size": weights_bytes.len(), "sha256": weights_sha }
        }
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let manifest_sha = sha256_hex(&manifest_bytes);
    fs::write(root.join("manifest.json"), &manifest_bytes).unwrap();

    let receipt = json!({
        "schemaVersion": 1,
        "manifestSha256": manifest_sha,
        "modelDirectoryPath": root.display().to_string(),
        "verificationTimestamp": "2026-11-25T18:00:00Z",
        "toolVersion": "0.1.0",
        "files": {
            "manifest.json": { "size": manifest_bytes.len(), "sha256": manifest_sha },
            "shard0.bin": { "size": weights_bytes.len(), "sha256": weights_sha }
        }
    });
    fs::write(
        root.join("verified-install.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();

    let report = verify_gturbo_directory(root, true).unwrap();
    assert_eq!(report.model_id, "gemma-4-26b-a4b-test");
    assert_eq!(report.verified_files, 2);

    // Tamper weights shard -> must fail SHA-256 verification.
    fs::write(root.join("shard0.bin"), b"GTURBO_TAMPERED_DATA_XXXX").unwrap();
    let err = verify_gturbo_directory(root, true).unwrap_err();
    assert!(matches!(err, AppError::ModelIntegrity(_)));
}

#[test]
fn test_host_origin_and_constant_time_bearer_guards() {
    assert!(validate_host_header(Some("127.0.0.1:8787"), false));
    assert!(validate_host_header(Some("localhost:8787"), false));
    assert!(validate_host_header(Some("[::1]:8787"), false));
    assert!(!validate_host_header(Some("evil.example:8787"), false));
    assert!(!validate_host_header(None, false));

    assert!(validate_origin_header(None, false));
    assert!(validate_origin_header(Some("http://127.0.0.1:3000"), false));
    assert!(!validate_origin_header(Some("https://evil.example"), false));

    let secret = Zeroizing::new("super-secret-token-123".to_string());
    assert!(constant_time_bearer_eq(
        Some("Bearer super-secret-token-123"),
        &secret
    ));
    assert!(!constant_time_bearer_eq(Some("Bearer wrong"), &secret));
    assert!(!constant_time_bearer_eq(None, &secret));
}

#[tokio::test]
async fn test_publish_dual_gate_lock() {
    let client_locked = SubstackClient::try_new(
        Some("testpub".to_string()),
        None,
        "substack.sid".to_string(),
        250,
        false,
    )
    .unwrap();
    let err1 = client_locked
        .publish_draft(None, "12345", false, true)
        .await
        .unwrap_err();
    assert!(matches!(err1, AppError::PublishLocked(_)));

    let client_unconfirmed = SubstackClient::try_new(
        Some("testpub".to_string()),
        None,
        "substack.sid".to_string(),
        250,
        true,
    )
    .unwrap();
    let err2 = client_unconfirmed
        .publish_draft(None, "12345", false, false)
        .await
        .unwrap_err();
    assert!(matches!(err2, AppError::PublishLocked(_)));
}

#[tokio::test]
async fn test_http_security_middleware_and_legacy_sse_roundtrip() {
    let token = "test-bearer-secret-9876";
    let (addr, ct, _handle) = spawn_test_server(false, Some(token));
    let client = reqwest::Client::builder().build().unwrap();

    // 1. /healthz succeeds without auth and includes strict security headers.
    let hz = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(hz.status(), StatusCode::OK);
    assert_eq!(
        hz.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(hz.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(hz.headers().get("cache-control").unwrap(), "no-store");

    // 2. Spoofed Host header blocked (DNS rebinding mitigation).
    let bad_host = client
        .get(format!("http://{addr}/healthz"))
        .header("Host", "rebind.evil.com")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_host.status(), StatusCode::FORBIDDEN);

    // 3. Cross-origin Origin header blocked (CSWSH mitigation).
    let bad_origin = client
        .get(format!("http://{addr}/sse"))
        .header("Origin", "https://attacker.example")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

    // 4. Protected routes enforce Bearer auth.
    let unauth = client
        .get(format!("http://{addr}/sse"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // 4b. Oversized body (> 2 MiB) is rejected with 413 Payload Too Large.
    let oversized = "a".repeat(2 * 1024 * 1024 + 1024);
    let too_large = client
        .post(format!(
            "http://{addr}/message?sessionId=00000000-0000-0000-0000-000000000000"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .body(oversized)
        .send()
        .await
        .unwrap();
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 5. Legacy SSE connect + POST /message tool call roundtrip.
    let sse_resp = client
        .get(format!("http://{addr}/sse"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);

    let mut stream = sse_resp.bytes_stream();
    let first_chunk = stream.next().await.unwrap().unwrap();
    let first_text = String::from_utf8_lossy(&first_chunk);
    let data_line = first_text
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("SSE endpoint event");
    let post_url = format!("http://{addr}{}", data_line.trim());

    let rpc_req = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "editor_analyze_markdown",
            "arguments": {
                "markdown": "# Audit Test\n\nClean zero-unsafe Rust pipeline."
            }
        }
    });
    let accepted = client
        .post(&post_url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&rpc_req)
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let msg_chunk = stream.next().await.unwrap().unwrap();
    let msg_text = String::from_utf8_lossy(&msg_chunk);
    let json_line = msg_text
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("SSE response message");
    let parsed: Value = serde_json::from_str(json_line.trim()).unwrap();
    assert_eq!(parsed["id"], 42);
    let inner_text = parsed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(inner_text.contains("builtin-small-editor-v1"));
    assert!(inner_text.contains("audit-test"));

    ct.cancel();
}

#[tokio::test]
async fn test_mcp_2_0_streamable_http_client_roundtrip() {
    use rmcp::{
        ClientLifecycleMode, ClientServiceExt,
        model::{
            CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation,
            ProtocolVersion,
        },
        transport::StreamableHttpClientTransport,
    };

    let (addr, ct, _handle) = spawn_test_server(false, None);
    let transport = StreamableHttpClientTransport::from_uri(format!("http://{addr}/mcp"));
    let client_cfg = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("substack-mcp-test-client", "0.1.0"),
    );
    let client = client_cfg
        .serve_with_lifecycle(
            transport,
            ClientLifecycleMode::Auto {
                preferred_versions: vec![ProtocolVersion::V_2025_11_25],
                legacy_version: Some(ProtocolVersion::V_2024_11_05),
            },
        )
        .await
        .unwrap();

    let tools = client.list_tools(None).await.unwrap();
    assert!(tools.tools.len() >= 11);

    let call = CallToolRequestParams::new("editor_to_prosemirror").with_arguments(
        serde_json::json!({
            "markdown": "## Verified\n\nPure Rust AST."
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let result = client.call_tool(call).await.unwrap();
    let out_str = serde_json::to_string(&result).unwrap();
    assert!(out_str.contains("Pure Rust AST."));

    let _ = client.cancel().await;
    ct.cancel();
}
