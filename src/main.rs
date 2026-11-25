#![forbid(unsafe_code)]

use axum::http::header;
use clap::{Parser, Subcommand, ValueEnum};
use reqwest::redirect::Policy;
use rmcp::{
    ClientLifecycleMode, ClientServiceExt, ServiceExt,
    model::{
        CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation, ProtocolVersion,
    },
    transport::{
        StreamableHttpClientTransport, TokioChildProcess, stdio,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Map, Value};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use substack_mcp_rs::editor::SmallEditorModel;
use substack_mcp_rs::editor::prosemirror::{DEFAULT_MAX_MARKDOWN_BYTES, markdown_to_prosemirror};
use substack_mcp_rs::error::AppError;
use substack_mcp_rs::mcp::SubstackMcpServer;
use substack_mcp_rs::mcp::http::{DEFAULT_MAX_BODY_BYTES, HttpSecurityConfig, build_router};
use substack_mcp_rs::security::SecretCookie;
use substack_mcp_rs::substack::SubstackClient;
use substack_mcp_rs::turbo_fieldfare::{TurboFieldfareClient, verify_gturbo_directory};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "substack-mcp-rs",
    version,
    about = "Agent-agnostic Rust Substack MCP 2.0 (Streamable HTTP + SSE + stdio) server & client with Small Editor Model & TurboFieldfare integration"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, ValueEnum)]
enum ServeTransport {
    Stdio,
    Http,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the hardened MCP 2.0 + Legacy SSE + stdio server
    Serve {
        #[arg(long, value_enum, default_value_t = ServeTransport::Stdio)]
        transport: ServeTransport,
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: SocketAddr,
        #[arg(long)]
        allow_non_loopback: bool,
        #[arg(long, env = "MCP_AUTH_TOKEN")]
        auth_token: Option<String>,
        #[arg(long, env = "SUBSTACK_PUBLICATION")]
        publication: Option<String>,
        #[arg(long, env = "SUBSTACK_SID")]
        sid: Option<String>,
        #[arg(long, default_value = "substack.sid")]
        cookie_name: String,
        #[arg(long)]
        allow_publish: bool,
        #[arg(long, env = "TURBO_FIELDFARE_URL")]
        turbo_fieldfare_url: Option<String>,
        #[arg(long)]
        turbo_fieldfare_model: Option<String>,
        #[arg(long, default_value_t = 1500)]
        rate_limit_ms: u64,
    },
    /// Agent-agnostic MCP 2.0 Streamable HTTP / stdio client
    Client {
        #[arg(long, default_value = "http://127.0.0.1:8787/mcp")]
        url: String,
        /// Optional stdio MCP command to launch cleanly (disables HTTP transport when set)
        #[arg(long)]
        stdio_cmd: Option<String>,
        #[arg(long)]
        stdio_args: Vec<String>,
        #[arg(long, env = "MCP_AUTH_TOKEN")]
        auth_token: Option<String>,
        #[command(subcommand)]
        action: ClientAction,
    },
    /// Run offline pure-Rust Small Editor Model commands on local Markdown files
    Editor {
        #[command(subcommand)]
        action: EditorAction,
    },
    /// Verify a drumih/turbo-fieldfare .gturbo model directory before local inference
    VerifyGturbo {
        directory: PathBuf,
        #[arg(long)]
        size_only: bool,
    },
    /// Benchmark pure-Rust ProseMirror AST compilation & Small Editor Model throughput
    Bench {
        #[arg(long, default_value_t = 5000)]
        iterations: usize,
    },
}

#[derive(Subcommand)]
enum ClientAction {
    ListTools,
    ListResources,
    ListPrompts,
    Call {
        tool: String,
        #[arg(long, default_value = "{}")]
        args_json: String,
    },
}

#[derive(Subcommand)]
enum EditorAction {
    Analyze { file: PathBuf },
    ToProsemirror { file: PathBuf },
    Polish { file: PathBuf },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Commands::Serve {
            transport,
            bind,
            allow_non_loopback,
            auth_token,
            publication,
            sid,
            cookie_name,
            allow_publish,
            turbo_fieldfare_url,
            turbo_fieldfare_model,
            rate_limit_ms,
        } => {
            let cookie = sid.as_deref().map(SecretCookie::try_new).transpose()?;
            let substack = Arc::new(SubstackClient::try_new(
                publication,
                cookie,
                cookie_name,
                rate_limit_ms,
                allow_publish,
            )?);
            let tf = turbo_fieldfare_url
                .as_deref()
                .map(|u| TurboFieldfareClient::try_new(u, turbo_fieldfare_model.as_deref()))
                .transpose()?
                .map(Arc::new);
            let mcp = SubstackMcpServer::new(substack, tf);

            match transport {
                ServeTransport::Stdio => {
                    let running = mcp
                        .serve(stdio())
                        .await
                        .map_err(|e| AppError::Http(e.to_string()))?;
                    let _ = running.waiting().await;
                    Ok(())
                }
                ServeTransport::Http => {
                    if !bind.ip().is_loopback() && !allow_non_loopback {
                        return Err(AppError::SsrfBlocked(
                            "refusing non-loopback bind without --allow-non-loopback".to_string(),
                        ));
                    }
                    let bearer_token = auth_token
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .map(Zeroizing::new);
                    if allow_non_loopback && bearer_token.is_none() {
                        return Err(AppError::AuthRequired(
                            "--allow-non-loopback requires --auth-token or MCP_AUTH_TOKEN"
                                .to_string(),
                        ));
                    }
                    let sec = HttpSecurityConfig {
                        allow_non_loopback,
                        bearer_token,
                        max_body_bytes: DEFAULT_MAX_BODY_BYTES,
                    };
                    let ct = CancellationToken::new();
                    let router = build_router(mcp, sec, ct.clone());
                    let listener = tokio::net::TcpListener::bind(bind).await?;
                    let local_addr = listener.local_addr()?;
                    tracing::info!(
                        addr = %local_addr,
                        "listening on /mcp (MCP 2.0 Streamable HTTP), /sse + /message (Legacy SSE), /healthz"
                    );
                    axum::serve(listener, router)
                        .with_graceful_shutdown(async move {
                            let _ = tokio::signal::ctrl_c().await;
                            ct.cancel();
                        })
                        .await?;
                    Ok(())
                }
            }
        }
        Commands::Client {
            url,
            stdio_cmd,
            stdio_args,
            auth_token,
            action,
        } => run_client(url, stdio_cmd, stdio_args, auth_token, action).await,
        Commands::Editor { action } => match action {
            EditorAction::Analyze { file } => {
                let md = fs::read_to_string(file)?;
                let report = SmallEditorModel::analyze(&md)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            EditorAction::ToProsemirror { file } => {
                let md = fs::read_to_string(file)?;
                let out = markdown_to_prosemirror(&md, DEFAULT_MAX_MARKDOWN_BYTES)?;
                println!("{}", serde_json::to_string_pretty(&out)?);
                Ok(())
            }
            EditorAction::Polish { file } => {
                let md = fs::read_to_string(file)?;
                let polished = SmallEditorModel::deterministic_polish(&md)?;
                println!("{}", serde_json::to_string_pretty(&polished)?);
                Ok(())
            }
        },
        Commands::VerifyGturbo {
            directory,
            size_only,
        } => {
            let report = verify_gturbo_directory(&directory, !size_only)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Commands::Bench { iterations } => run_bench(iterations),
    }
}

async fn run_client(
    url: String,
    stdio_cmd: Option<String>,
    stdio_args: Vec<String>,
    auth_token: Option<String>,
    action: ClientAction,
) -> Result<(), AppError> {
    let client_cfg = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("substack-mcp-rs-client", env!("CARGO_PKG_VERSION")),
    );
    let lifecycle = ClientLifecycleMode::Auto {
        preferred_versions: vec![ProtocolVersion::V_2025_11_25],
        legacy_version: Some(ProtocolVersion::V_2024_11_05),
    };

    if let Some(bin) = stdio_cmd {
        let mut cmd = Command::new(bin);
        cmd.args(stdio_args);
        let transport = TokioChildProcess::new(cmd).map_err(AppError::Io)?;
        let client = client_cfg
            .serve_with_lifecycle(transport, lifecycle)
            .await
            .map_err(|e| AppError::Http(e.to_string()))?;
        return exec_client_action(client, action).await;
    }

    let mut headers = header::HeaderMap::new();
    if let Some(tok) = auth_token.filter(|t| !t.trim().is_empty()) {
        let val = header::HeaderValue::from_str(&format!("Bearer {}", tok.trim()))
            .map_err(|e| AppError::InvalidConfig(format!("invalid auth token header: {e}")))?;
        headers.insert(header::AUTHORIZATION, val);
    }
    let reqwest_client = reqwest::Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .default_headers(headers)
        .build()
        .map_err(|e| AppError::Http(e.to_string()))?;

    let transport = StreamableHttpClientTransport::with_client(
        reqwest_client,
        StreamableHttpClientTransportConfig::with_uri(url),
    );
    let client = client_cfg
        .serve_with_lifecycle(transport, lifecycle)
        .await
        .map_err(|e| AppError::Http(e.to_string()))?;
    exec_client_action(client, action).await
}

async fn exec_client_action<S>(
    client: rmcp::service::RunningService<rmcp::RoleClient, S>,
    action: ClientAction,
) -> Result<(), AppError>
where
    S: rmcp::service::Service<rmcp::RoleClient>,
{
    match action {
        ClientAction::ListTools => {
            let res = client
                .list_tools(None)
                .await
                .map_err(|e| AppError::Http(e.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        ClientAction::ListResources => {
            let res = client
                .list_resources(None)
                .await
                .map_err(|e| AppError::Http(e.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        ClientAction::ListPrompts => {
            let res = client
                .list_prompts(None)
                .await
                .map_err(|e| AppError::Http(e.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        ClientAction::Call { tool, args_json } => {
            let parsed: Value = serde_json::from_str(&args_json)?;
            let map: Map<String, Value> = parsed.as_object().cloned().ok_or_else(|| {
                AppError::InvalidConfig("--args-json must be a JSON object".to_string())
            })?;
            let res = client
                .call_tool(CallToolRequestParams::new(tool).with_arguments(map))
                .await
                .map_err(|e| AppError::Http(e.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
    }
    let _ = client.cancel().await;
    Ok(())
}

fn run_bench(iterations: usize) -> Result<(), AppError> {
    let iters = iterations.max(1);
    let sample = "# Securing Hardware CFI Across Mobile Kernels\n\n\
Modern ARM64 kernels enforce **W^X** isolation, Pointer Authentication (`paciasp`), \
and strict IPC boundary validation. This essay reviews empirical telemetry across \
[ARM architecture docs](https://developer.arm.com/documentation/) and Apple SPTM.\n\n\
## 1. Key Findings\n\n\
- Zero `PF_W | PF_X` segments observed across HAL binaries.\n\
- Deterministic ProseMirror compilation avoids broken inline marks.\n\n\
```rust\nfn verify_alignment(align: u64) -> bool { align >= 0x4000 }\n```\n";

    let t0 = Instant::now();
    let mut total_bytes = 0usize;
    let mut total_blocks = 0usize;
    for _ in 0..iters {
        let out = markdown_to_prosemirror(sample, DEFAULT_MAX_MARKDOWN_BYTES)?;
        total_bytes += sample.len();
        total_blocks += out.block_count;
    }
    let pm_elapsed = t0.elapsed();

    let t1 = Instant::now();
    let mut total_words = 0usize;
    for _ in 0..iters {
        let report = SmallEditorModel::analyze(sample)?;
        total_words += report.word_count;
    }
    let ed_elapsed = t1.elapsed();

    let pm_docs_per_sec = (iters as f64) / pm_elapsed.as_secs_f64();
    let pm_mib_per_sec = (total_bytes as f64) / (1024.0 * 1024.0) / pm_elapsed.as_secs_f64();
    let ed_us_per_doc = (ed_elapsed.as_secs_f64() * 1_000_000.0) / (iters as f64);

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "iterations": iters,
            "sample_bytes": sample.len(),
            "prosemirror_compile": {
                "elapsed_ms": (pm_elapsed.as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
                "docs_per_sec": (pm_docs_per_sec * 100.0).round() / 100.0,
                "throughput_mib_per_sec": (pm_mib_per_sec * 100.0).round() / 100.0,
                "total_blocks_emitted": total_blocks,
            },
            "small_editor_analyze": {
                "elapsed_ms": (ed_elapsed.as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
                "us_per_doc": (ed_us_per_doc * 100.0).round() / 100.0,
                "total_words_scored": total_words,
            }
        }))?
    );
    Ok(())
}
