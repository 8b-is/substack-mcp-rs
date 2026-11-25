# Contributing to `substack-mcp-rs`

Thank you for helping keep `substack-mcp-rs` fast, agent-agnostic, and free of vulnerabilities.

## Engineering Rules

1. **Zero `unsafe` code**: `#![forbid(unsafe_code)]` is non-negotiable.
2. **Zero unwrap/expect/panic in production paths**: Follow crate-level Clippy rules (`unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`).
3. **Pure-Rust TLS only**: Never introduce OpenSSL or dynamic C TLS dependencies (`deny.toml` forbids `openssl`/`openssl-sys`).
4. **Always pair behavioral changes with security regression tests** in `tests/security_audit.rs`.

## Local Pre-PR Checklist

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo audit
cargo deny check
gitleaks detect --source . --verbose
```
