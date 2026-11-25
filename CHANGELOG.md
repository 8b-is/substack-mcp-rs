# Changelog

## v0.1.0 (2026-11-25)

### Added
- Pure-Rust MCP 2.0 Streamable HTTP (`/mcp`), Legacy HTTP+SSE (`/sse` + `/message`), and `stdio` server + client (`rmcp 3.11.0`, `axum 0.8.9`).
- Built-in zero-network **Small Editor Model** (`editor_analyze_markdown`, `editor_to_prosemirror`, `editor_refine_draft`) with single-pass `pulldown-cmark` -> Substack ProseMirror AST compilation, HTML/XSS stripping, Flesch-Kincaid scoring, AI-cliché linting, and code-fence-preserving polish.
- [`drumih/turbo-fieldfare`](https://github.com/drumih/turbo-fieldfare) integration:
  - `.gturbo` directory integrity verifier (`turbo_verify_gturbo_package` / `verify-gturbo`) enforcing symlink rejection, path-traversal checks, 4 MiB metadata caps, and 64 KiB streaming SHA-256 shard verification.
  - Loopback-restricted `TurboFieldfareServer` (`/v1/chat/completions`) client with indirect prompt-injection delimiters (`<draft_content>`) and automatic offline fallback.
- Security audit regression suite (`tests/security_audit.rs`), `deny.toml` policy, GitHub Actions CI + Security (`cargo-audit`, `cargo-deny`, `gitleaks`, CodeQL, Trivy) + SLSA provenance release workflows.
