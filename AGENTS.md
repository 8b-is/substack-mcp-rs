# AGENTS.md — `substack-mcp-rs`

Pure-Rust, zero-unsafe (`#![forbid(unsafe_code)]`) Substack MCP 2.0 (Streamable HTTP + Legacy SSE + `stdio`) server, CLI client, built-in Small Editor Model, and `drumih/turbo-fieldfare` loopback inference integration.

## Toolchain & Rules

- Edition `2024`, Rust `1.88+`, zero OpenSSL (`rustls` only).
- Crate lints forbid `unsafe_code`, `unwrap()`, `expect()`, and `panic!()` in production code.
- Always run before committing:
  ```bash
  cargo fmt --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-targets
  cargo audit
  cargo deny check
  gitleaks detect --source . --verbose
  ```
- Never commit live `SUBSTACK_SID` cookies or `MCP_AUTH_TOKEN` secrets.
- Always use `git -c user.name="Peter Lodri" -c user.email="267054113+peterlodri-sec@users.noreply.github.com"` when committing if git global email isn't noreply (prevents GitHub GH007 push rejections).
