pub mod http;

use crate::editor::SmallEditorModel;
use crate::editor::prosemirror::{DEFAULT_MAX_MARKDOWN_BYTES, markdown_to_prosemirror};
use crate::error::AppError;
use crate::substack::SubstackClient;
use crate::turbo_fieldfare::{TurboFieldfareClient, verify_gturbo_directory};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{
        router::{prompt::PromptRouter, tool::ToolRouter},
        wrapper::Parameters,
    },
    model::{
        CallToolResult, ContentBlock, ErrorCode, Implementation, InitializeRequestParams,
        InitializeResult, ListResourceTemplatesResult, ListResourcesResult, PaginatedRequestParams,
        Prompt, PromptMessage, ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse,
        ReadResourceResult, Resource, ResourceContents, Role, ServerCapabilities, ServerConfig,
        Tool,
    },
    prompt, prompt_handler, prompt_router, schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct ServerTelemetry {
    pub tool_calls: AtomicU64,
    pub prosemirror_compilations: AtomicU64,
    pub editor_runs: AtomicU64,
}

#[derive(Clone)]
pub struct SubstackMcpServer {
    substack: Arc<SubstackClient>,
    turbo_fieldfare: Option<Arc<TurboFieldfareClient>>,
    telemetry: Arc<ServerTelemetry>,
    tool_router: ToolRouter<Self>,
    prompt_router: PromptRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EmptyArgs {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListItemsArgs {
    /// Publication subdomain (single lowercase DNS label, e.g. `mynewsletter`)
    pub publication: Option<String>,
    /// Maximum entries per page (1..=50)
    pub limit: Option<u32>,
    /// Zero-based pagination offset
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DraftIdArgs {
    /// Publication subdomain (single lowercase DNS label)
    pub publication: Option<String>,
    /// Numeric or slug draft identifier
    pub draft_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateDraftArgs {
    /// Publication subdomain (single lowercase DNS label)
    pub publication: Option<String>,
    /// Post headline / title
    pub title: String,
    /// Optional subtitle
    pub subtitle: Option<String>,
    /// Newsletter body in CommonMark Markdown (sanitized and compiled to ProseMirror AST)
    pub markdown: String,
    /// Audience (`everyone` or `only_paid`)
    pub audience: Option<String>,
    /// When true, validates and compiles without calling Substack HTTP API
    pub dry_run: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateDraftArgs {
    /// Publication subdomain (single lowercase DNS label)
    pub publication: Option<String>,
    /// Draft ID to update
    pub draft_id: String,
    /// Updated post title
    pub title: String,
    /// Optional updated subtitle
    pub subtitle: Option<String>,
    /// Updated body in CommonMark Markdown
    pub markdown: String,
    /// When true, validates and compiles without calling Substack HTTP API
    pub dry_run: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PublishDraftArgs {
    /// Publication subdomain (single lowercase DNS label)
    pub publication: Option<String>,
    /// Draft ID to publish
    pub draft_id: String,
    /// Send newsletter email to subscribers (`false` = web post only)
    pub send_email: Option<bool>,
    /// Explicit per-call safeguard confirmation (`true` required alongside `--allow-publish`)
    pub confirm_publish: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MarkdownInputArgs {
    /// Markdown content to analyze or compile (max 1 MiB)
    pub markdown: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RefineDraftArgs {
    /// Editorial goal (e.g. `tighten technical clarity and preserve citations`)
    pub goal: Option<String>,
    /// Markdown draft body to refine
    pub markdown: String,
    /// Maximum tokens for local TurboFieldfare Gemma inference (default 1024)
    pub max_tokens: Option<u32>,
    /// Skip loopback TurboFieldfare HTTP call and run purely deterministic Rust editor
    pub offline_only: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyGturboArgs {
    /// Local path to a `.gturbo` model directory
    pub directory: String,
    /// Perform full streaming SHA-256 verification across all shard files (default true)
    pub full_sha256: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EditorialPromptArgs {
    /// Draft headline
    pub draft_title: String,
    /// Markdown draft text
    pub markdown: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PackagingPromptArgs {
    /// Core thesis or technical topic
    pub topic: String,
    /// Target reader persona
    pub target_audience: Option<String>,
}

fn json_text_result<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let serialized = serde_json::to_string_pretty(value)
        .map_err(|e| McpError::internal_error(format!("JSON serialization failed: {e}"), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serialized,
    )]))
}

#[tool_router]
impl SubstackMcpServer {
    pub fn new(
        substack: Arc<SubstackClient>,
        turbo_fieldfare: Option<Arc<TurboFieldfareClient>>,
    ) -> Self {
        Self {
            substack,
            turbo_fieldfare,
            telemetry: Arc::new(ServerTelemetry::default()),
            tool_router: Self::tool_router(),
            prompt_router: Self::prompt_router(),
        }
    }

    pub fn listed_tools(&self) -> Vec<Tool> {
        self.tool_router.list_all()
    }

    pub fn listed_prompts(&self) -> Vec<Prompt> {
        self.prompt_router.list_all()
    }

    #[tool(
        description = "Verify configured Substack session cookie via GET /api/v1/user/profile/self"
    )]
    async fn substack_verify_session(
        &self,
        #[allow(unused_variables)] Parameters(_args): Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .substack
            .verify_session()
            .await
            .map_err(McpError::from)?;
        json_text_result(&resp)
    }

    #[tool(description = "List newsletter drafts for a validated *.substack.com publication")]
    async fn substack_list_drafts(
        &self,
        Parameters(args): Parameters<ListItemsArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .substack
            .list_drafts(
                args.publication.as_deref(),
                args.limit.unwrap_or(20),
                args.offset.unwrap_or(0),
            )
            .await
            .map_err(McpError::from)?;
        json_text_result(&resp)
    }

    #[tool(description = "Fetch a single Substack draft by ID")]
    async fn substack_get_draft(
        &self,
        Parameters(args): Parameters<DraftIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .substack
            .get_draft(args.publication.as_deref(), &args.draft_id)
            .await
            .map_err(McpError::from)?;
        json_text_result(&resp)
    }

    #[tool(
        description = "Compile sanitized Markdown to Substack ProseMirror JSON and create a draft (supports dry_run)"
    )]
    async fn substack_create_draft(
        &self,
        Parameters(args): Parameters<CreateDraftArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        self.telemetry
            .prosemirror_compilations
            .fetch_add(1, Ordering::Relaxed);
        let compiled = markdown_to_prosemirror(&args.markdown, DEFAULT_MAX_MARKDOWN_BYTES)
            .map_err(McpError::from)?;
        let resp = self
            .substack
            .create_draft(
                args.publication.as_deref(),
                &args.title,
                args.subtitle.as_deref(),
                &compiled.doc,
                args.audience.as_deref().unwrap_or("everyone"),
                args.dry_run.unwrap_or(false),
            )
            .await
            .map_err(McpError::from)?;
        json_text_result(&json!({
            "response": resp,
            "prosemirror_blocks": compiled.block_count,
            "stripped_unsafe_links": compiled.stripped_unsafe_links,
        }))
    }

    #[tool(
        description = "Compile sanitized Markdown to Substack ProseMirror JSON and update an existing draft (supports dry_run)"
    )]
    async fn substack_update_draft(
        &self,
        Parameters(args): Parameters<UpdateDraftArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        self.telemetry
            .prosemirror_compilations
            .fetch_add(1, Ordering::Relaxed);
        let compiled = markdown_to_prosemirror(&args.markdown, DEFAULT_MAX_MARKDOWN_BYTES)
            .map_err(McpError::from)?;
        let resp = self
            .substack
            .update_draft(
                args.publication.as_deref(),
                &args.draft_id,
                &args.title,
                args.subtitle.as_deref(),
                &compiled.doc,
                args.dry_run.unwrap_or(false),
            )
            .await
            .map_err(McpError::from)?;
        json_text_result(&json!({
            "response": resp,
            "prosemirror_blocks": compiled.block_count,
            "stripped_unsafe_links": compiled.stripped_unsafe_links,
        }))
    }

    #[tool(
        description = "Publish a Substack draft (dual-gated: requires --allow-publish at server boot AND confirm_publish=true)"
    )]
    async fn substack_publish_draft(
        &self,
        Parameters(args): Parameters<PublishDraftArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .substack
            .publish_draft(
                args.publication.as_deref(),
                &args.draft_id,
                args.send_email.unwrap_or(false),
                args.confirm_publish,
            )
            .await
            .map_err(McpError::from)?;
        json_text_result(&resp)
    }

    #[tool(
        description = "List public published posts for a Substack publication (no cookie required)"
    )]
    async fn substack_list_posts(
        &self,
        Parameters(args): Parameters<ListItemsArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .substack
            .list_posts(
                args.publication.as_deref(),
                args.limit.unwrap_or(20),
                args.offset.unwrap_or(0),
            )
            .await
            .map_err(McpError::from)?;
        json_text_result(&resp)
    }

    #[tool(
        description = "Run the zero-latency pure-Rust Small Editor Model analyzer on a Markdown draft"
    )]
    async fn editor_analyze_markdown(
        &self,
        Parameters(args): Parameters<MarkdownInputArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        self.telemetry.editor_runs.fetch_add(1, Ordering::Relaxed);
        let report = SmallEditorModel::analyze(&args.markdown).map_err(McpError::from)?;
        json_text_result(&report)
    }

    #[tool(
        description = "Compile Markdown into Substack-compatible ProseMirror JSON with XSS/URI sanitization"
    )]
    async fn editor_to_prosemirror(
        &self,
        Parameters(args): Parameters<MarkdownInputArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        self.telemetry
            .prosemirror_compilations
            .fetch_add(1, Ordering::Relaxed);
        let out = markdown_to_prosemirror(&args.markdown, DEFAULT_MAX_MARKDOWN_BYTES)
            .map_err(McpError::from)?;
        json_text_result(&out)
    }

    #[tool(
        description = "Refine a Substack draft using loopback TurboFieldfare Gemma 4 inference (if connected) or the built-in Small Editor Model"
    )]
    async fn editor_refine_draft(
        &self,
        Parameters(args): Parameters<RefineDraftArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        self.telemetry.editor_runs.fetch_add(1, Ordering::Relaxed);

        let offline_only = args.offline_only.unwrap_or(false);
        let goal = args.goal.as_deref().unwrap_or(
            "Tighten technical clarity, remove AI fluff, and keep all citations intact.",
        );

        if !offline_only && let Some(ref tf) = self.turbo_fieldfare {
            let before = SmallEditorModel::analyze(&args.markdown).map_err(McpError::from)?;
            match tf
                .refine_draft(goal, &args.markdown, args.max_tokens.unwrap_or(1024))
                .await
            {
                Ok((model_used, refined_markdown)) => {
                    let after =
                        SmallEditorModel::analyze(&refined_markdown).map_err(McpError::from)?;
                    return json_text_result(&json!({
                        "engine": "turbo-fieldfare-local",
                        "model": model_used,
                        "endpoint": tf.base_url().as_str(),
                        "polished_markdown": refined_markdown,
                        "before": before,
                        "after": after,
                    }));
                }
                Err(err) => {
                    let fallback = SmallEditorModel::deterministic_polish(&args.markdown)
                        .map_err(McpError::from)?;
                    return json_text_result(&json!({
                        "engine": fallback.engine,
                        "turbo_fieldfare_fallback_reason": err.to_string(),
                        "changes_applied": fallback.changes_applied,
                        "polished_markdown": fallback.polished_markdown,
                        "before": fallback.before,
                        "after": fallback.after,
                    }));
                }
            }
        }

        let res = SmallEditorModel::deterministic_polish(&args.markdown).map_err(McpError::from)?;
        json_text_result(&res)
    }

    #[tool(
        description = "Verify a drumih/turbo-fieldfare .gturbo model directory against manifest.json & verified-install.json SHA-256 digests"
    )]
    async fn turbo_verify_gturbo_package(
        &self,
        Parameters(args): Parameters<VerifyGturboArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.telemetry.tool_calls.fetch_add(1, Ordering::Relaxed);
        let report =
            verify_gturbo_directory(Path::new(&args.directory), args.full_sha256.unwrap_or(true))
                .map_err(McpError::from)?;
        json_text_result(&report)
    }
}

#[prompt_router]
impl SubstackMcpServer {
    #[prompt(name = "substack_editorial_review")]
    async fn substack_editorial_review(
        &self,
        Parameters(args): Parameters<EditorialPromptArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        Ok(vec![
            PromptMessage::new_text(
                Role::Assistant,
                "Review technical accuracy, prose tightness, and Substack ProseMirror readiness.",
            ),
            PromptMessage::new_text(
                Role::User,
                format!(
                    "Title: {}\n\nAnalyze structure, remove clichés, preserve code blocks/citations verbatim:\n\n{}",
                    args.draft_title, args.markdown
                ),
            ),
        ])
    }

    #[prompt(name = "substack_newsletter_packaging")]
    async fn substack_newsletter_packaging(
        &self,
        Parameters(args): Parameters<PackagingPromptArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let audience = args
            .target_audience
            .as_deref()
            .unwrap_or("systems & security engineers");
        Ok(vec![PromptMessage::new_text(
            Role::User,
            format!(
                "Generate 3 crisp, non-clickbait Substack titles, 1-sentence subtitles, and a URL slug for topic `{}` targeting `{audience}`.",
                args.topic
            ),
        )])
    }
}

#[tool_handler]
#[prompt_handler]
impl ServerHandler for SubstackMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("substack-mcp-rs", env!("CARGO_PKG_VERSION")))
        .with_protocol_version(ProtocolVersion::V_2025_11_25)
        .with_instructions(
            "Agent-agnostic Substack MCP 2.0 server with built-in pure-Rust Small Editor Model, ProseMirror AST compiler, and TurboFieldfare loopback inference.".to_string(),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: Self::resource_catalog(),
            ..Default::default()
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        let text = self
            .read_resource_text(&request.uri)
            .map_err(McpError::from)?;
        Ok(ReadResourceResult::new(vec![ResourceContents::text(text, request.uri.clone())]).into())
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult {
            resource_templates: Vec::new(),
            ..Default::default()
        })
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }
}

impl SubstackMcpServer {
    fn resource_catalog() -> Vec<Resource> {
        vec![
            Resource::new(
                "substack://editor/schema",
                "Substack ProseMirror AST Schema",
            ),
            Resource::new("substack://security/posture", "Runtime Security Posture"),
        ]
    }

    fn read_resource_text(&self, uri: &str) -> Result<String, AppError> {
        match uri {
            "substack://editor/schema" => Ok(serde_json::to_string_pretty(&json!({
                "root": "doc",
                "blocks": ["paragraph", "heading(1..6)", "bullet_list", "ordered_list", "list_item", "blockquote", "code_block", "horizontal_rule", "hard_break", "image"],
                "marks": ["strong", "em", "code", "link(https|http|mailto|relative)"],
                "max_markdown_bytes": DEFAULT_MAX_MARKDOWN_BYTES,
                "raw_html_stripped": true
            }))?),
            "substack://security/posture" => Ok(serde_json::to_string_pretty(&json!({
                "unsafe_code": "forbidden (#![forbid(unsafe_code)])",
                "tls_backend": "rustls (zero OpenSSL)",
                "redirects": "disabled",
                "publish_locked_default": !self.substack.allow_publish(),
                "substack_cookie_configured": self.substack.has_cookie(),
                "turbo_fieldfare_loopback_configured": self.turbo_fieldfare.is_some(),
                "counters": {
                    "tool_calls": self.telemetry.tool_calls.load(Ordering::Relaxed),
                    "prosemirror_compilations": self.telemetry.prosemirror_compilations.load(Ordering::Relaxed),
                    "editor_runs": self.telemetry.editor_runs.load(Ordering::Relaxed),
                }
            }))?),
            other => Err(AppError::InvalidIdentifier(format!(
                "unknown resource URI `{other}`"
            ))),
        }
    }

    /// Dispatches legacy HTTP+SSE JSON-RPC 2.0 requests (`POST /message`) against the exact
    /// same validated tool/prompt/resource handlers used by Streamable HTTP `/mcp` and `stdio`.
    pub async fn dispatch_legacy_jsonrpc(&self, msg: &Value) -> Option<Value> {
        let method = msg.get("method").and_then(Value::as_str)?;
        let id = msg.get("id").cloned();

        // Notifications carry no `id` and expect no JSON-RPC response.
        let id = id?;
        let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));

        let outcome: Result<Value, McpError> = match method {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": { "listChanged": false },
                    "prompts": { "listChanged": false },
                    "resources": { "listChanged": false }
                },
                "serverInfo": {
                    "name": "substack-mcp-rs",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.listed_tools() })),
            "prompts/list" => Ok(json!({ "prompts": self.listed_prompts() })),
            "resources/list" => Ok(json!({ "resources": Self::resource_catalog() })),
            "resources/read" => {
                let uri = params.get("uri").and_then(Value::as_str).unwrap_or("");
                self.read_resource_text(uri)
                    .map(|text| json!({ "contents": [{ "uri": uri, "text": text }] }))
                    .map_err(McpError::from)
            }
            "tools/call" => {
                let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let raw_args = params
                    .get("arguments")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                self.dispatch_tool_object(tool_name, raw_args)
                    .await
                    .and_then(|res| {
                        serde_json::to_value(res).map_err(|e| {
                            McpError::internal_error(
                                format!("tool result encoding failed: {e}"),
                                None,
                            )
                        })
                    })
            }
            other => Err(McpError::new(
                ErrorCode::METHOD_NOT_FOUND,
                format!("unknown MCP method `{other}`"),
                None,
            )),
        };

        Some(match outcome {
            Ok(result) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result,
            }),
            Err(err) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": err.code.0,
                    "message": err.message,
                }
            }),
        })
    }

    async fn dispatch_tool_object(
        &self,
        name: &str,
        obj: Map<String, Value>,
    ) -> Result<CallToolResult, McpError> {
        let val = Value::Object(obj);
        match name {
            "substack_verify_session" => {
                let args: EmptyArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.substack_verify_session(Parameters(args)).await
            }
            "substack_list_drafts" => {
                let args: ListItemsArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.substack_list_drafts(Parameters(args)).await
            }
            "substack_get_draft" => {
                let args: DraftIdArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.substack_get_draft(Parameters(args)).await
            }
            "substack_create_draft" => {
                let args: CreateDraftArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.substack_create_draft(Parameters(args)).await
            }
            "substack_update_draft" => {
                let args: UpdateDraftArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.substack_update_draft(Parameters(args)).await
            }
            "substack_publish_draft" => {
                let args: PublishDraftArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.substack_publish_draft(Parameters(args)).await
            }
            "substack_list_posts" => {
                let args: ListItemsArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.substack_list_posts(Parameters(args)).await
            }
            "editor_analyze_markdown" => {
                let args: MarkdownInputArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.editor_analyze_markdown(Parameters(args)).await
            }
            "editor_to_prosemirror" => {
                let args: MarkdownInputArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.editor_to_prosemirror(Parameters(args)).await
            }
            "editor_refine_draft" => {
                let args: RefineDraftArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.editor_refine_draft(Parameters(args)).await
            }
            "turbo_verify_gturbo_package" => {
                let args: VerifyGturboArgs = serde_json::from_value(val)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                self.turbo_verify_gturbo_package(Parameters(args)).await
            }
            unknown => Err(McpError::invalid_params(
                format!("unknown MCP tool `{unknown}`"),
                None,
            )),
        }
    }
}
