# Security Policy

## Supported Versions

Security fixes are applied to the latest release tag and the `main` branch.

| Version | Supported |
|---------|-----------|
| `0.1.x` / `main` | Yes |
| Earlier unreleased commits | No |

## Architectural Security Commitments

1. **Zero `unsafe` Rust**: Enforced globally via `#![forbid(unsafe_code)]` in `src/lib.rs`, `src/main.rs`, `tests/`, and `Cargo.toml` lints.
2. **Pure `rustls` TLS**: OpenSSL (`openssl`, `openssl-sys`) is explicitly banned in `deny.toml`.
3. **Strict SSRF Prevention**:
   - Substack subdomains must match `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$` (dots, IP literals, userinfo `@`, slashes, uppercase, non-ASCII blocked).
   - `TurboFieldfareServer` connections are restricted strictly to `http://127.0.0.1`, `http://[::1]`, or `http://localhost`.
   - HTTP redirects are disabled (`Policy::none()`) on all outbound clients.
4. **Secret Hygiene**: `SUBSTACK_SID` cookies are wrapped in `Zeroizing<String>` inside `SecretCookie`, rejected on CR/LF/NUL/semicolon header-injection bytes, and redact all `Debug`/`Display` output to `[REDACTED]`.
5. **Dual-Gated Publishing**: `substack_publish_draft` is locked by default and fails unless BOTH `--allow-publish` was set at server boot AND `confirm_publish: true` is passed per invocation.
6. **HTTP/SSE Transport Hardening**: Loopback-only default bind, strict `Host` (DNS rebinding guard) and `Origin` (CSWSH guard) validation, constant-time SHA-256-normalized Bearer authentication (`subtle::ConstantTimeEq`), `2 MiB` body cap, `128` concurrency limit, `64` max SSE sessions, and strict response security headers (`nosniff`, `no-store`, `DENY`, `default-src 'none'`).
7. **Model Package Integrity**: `.gturbo` directories reject symlinks, block path traversal (`..`, `/`, `\`), cap metadata reads at `4 MiB`, and perform 64 KiB streaming SHA-256 verification.

## Reporting a Vulnerability

Do **not** open a public GitHub issue for security vulnerabilities. Please use [GitHub Private Vulnerability Reporting](https://github.com/8b-is/substack-mcp-rs/security/advisories/new).

Include affected commit/version, reproduction steps, expected vs. actual behavior, and impact. Never include live session cookies (`substack.sid` / `connect.sid`) or bearer tokens in reports.
