# Pre-Release Security Audit & Attack Surface Reduction (`v0.1.0`)

**Auditor Target**: `github.com/8b-is/substack-mcp-rs` (`v0.1.0`)  
**Audit Date**: `2026-11-25`  
**Toolchain**: `rustc 1.99.0`, `cargo-audit 0.23.0`, `cargo-deny 0.22.1`, `gitleaks 8.30.1`, `xmllint`

---

## 1. Executive Summary & Attack Surface Posture

| Security Control / Boundary | Status | Enforcement Mechanism | Verification Evidence |
|-----------------------------|--------|-----------------------|-----------------------|
| Memory Safety (`unsafe` Rust) | **Zero `unsafe` (`0`)** | `#![forbid(unsafe_code)]` in `Cargo.toml`, `src/lib.rs`, `src/main.rs`, `tests/security_audit.rs` | Compiler-enforced at crate & module boundary |
| Panic / Unwrap Elimination | **Denied in prod** | Clippy `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"` | `cargo clippy --all-targets --all-features -- -D warnings` exit `0` |
| C TLS / OpenSSL Surface | **Zero OpenSSL (`0`)** | Pure-Rust `rustls` (`reqwest` `default-features = false`); `openssl`/`openssl-sys` banned in `deny.toml` | `cargo deny check bans` -> `ok` |
| HTTP Redirects / Open Redirects | **Disabled** | `reqwest::redirect::Policy::none()` on both `SubstackClient` and `TurboFieldfareClient` | Verified across `src/substack/mod.rs` & `src/turbo_fieldfare/mod.rs` |
| Subdomain / Host SSRF | **Blocked** | `validate_subdomain` enforces `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`, blocking dots, IPs, `@`, slashes, unicode | `test_ssrf_subdomain_validation_blocks_attacks` |
| Local Inference SSRF (`TurboFieldfare`) | **Loopback-only** | `validate_loopback_endpoint` allows only `http://127.0.0.1`, `http://[::1]`, or `http://localhost` | `test_loopback_endpoint_ssrf_guard` |
| Session Cookie Hygiene | **Zeroized & Redacted** | `SecretCookie(Zeroizing<String>)` rejects CR/LF/NUL/`;`/non-ASCII and formats `Debug`/`Display` as `[REDACTED]` | `test_cookie_header_injection_and_secret_redaction` |
| Indirect Prompt Injection Isolation | **Delimited** | `TurboFieldfareClient::refine_draft` wraps untrusted draft body in `<draft_content>...</draft_content>` with system boundary | `src/turbo_fieldfare/mod.rs` |
| Markdown / ProseMirror XSS | **Stripped / Blocked** | `pulldown-cmark` raw HTML events dropped; `validate_safe_link` blocks `javascript:`, `vbscript:`, `data:`, `file:`, `//` | `test_safe_link_and_prosemirror_xss_neutralization` |
| `.gturbo` Weights Integrity | **Strict SHA-256 + Anti-Traversal** | Rejects symlinks, `..`, `/`, `\`, hidden paths; 4 MiB metadata cap; 64 KiB streaming `Sha256` against `manifest.json` + `verified-install.json` | `test_gturbo_manifest_integrity_and_traversal_guards` |
| Draft Publish Safeguard | **Dual-Gated (Locked by Default)** | `substack_publish_draft` requires BOTH `--allow-publish` at startup AND `confirm_publish: true` per call | `test_publish_dual_gate_lock` |
| DNS Rebinding & CSWSH | **Blocked** | Middleware enforces `validate_host_header` and `validate_origin_header` (403 Forbidden on mismatch) | `test_http_security_middleware_and_legacy_sse_roundtrip` |
| Bearer Token Auth | **Length-Hiding Constant-Time** | Mandatory with `--allow-non-loopback`; compares `SHA-256` digests via `subtle::ConstantTimeEq` | `test_host_origin_and_constant_time_bearer_guards` |
| Resource / DoS Bounding | **Capped** | `2 MiB` HTTP body cap (413), `4 MiB` upstream response cap, `128` max concurrent requests, `64` max SSE sessions (`64`-item bounded queue) | `test_http_security_middleware_and_legacy_sse_roundtrip` (`413` verified) |
| HTTP Security Headers | **Enforced on All Routes** | `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'` | `test_http_security_middleware_and_legacy_sse_roundtrip` |

---

## 2. STRIDE Threat Model

| STRIDE Threat | Concrete Attack Vector | Mitigation in `substack-mcp-rs` |
|---------------|------------------------|---------------------------------|
| **Spoofing** | Malicious web page opens loopback `/sse` or `/mcp` (CSWSH / DNS rebinding) | `validate_host_header` + `validate_origin_header` reject foreign hosts/origins (`403`); `--allow-non-loopback` requires `MCP_AUTH_TOKEN` checked via `Sha256` + `ConstantTimeEq` |
| **Tampering** | Compromised `.gturbo` shard file or symlink in model directory; crafted Markdown `<script>` or `javascript:` URI | `verify_gturbo_directory` rejects symlinks/traversal and verifies streaming SHA-256; `markdown_to_prosemirror` strips raw HTML and disallowed URI schemes |
| **Repudiation / Accidental Blast** | Autonomous LLM agent accidentally triggers live Substack email blast | `substack_publish_draft` fails with `AppError::PublishLocked` unless both boot flag `--allow-publish` AND `confirm_publish: true` are set; `dry_run: true` supported on create/update |
| **Information Disclosure** | Error messages or debug logs leak `SUBSTACK_SID` / `connect.sid` or bearer tokens | `SecretCookie` implements custom `Debug`/`Display` (`[REDACTED]`) and `Zeroize` drop; middleware never logs `Authorization` or `Cookie` headers |
| **Denial of Service** | 100 MB payload / Slowloris / unbounded SSE sessions / upstream API flood | `2 MiB` body cap (HTTP 413), `128` concurrency limit, `64` max SSE sessions with `Drop` cleanup & `try_send` backpressure, `4 MiB` upstream read cap, upstream min-interval rate limiter (`1500 ms` default) |
| **Elevation of Privilege / SSRF** | Attacker passes `publication = "169.254.169.254#"` or non-loopback `--turbo-fieldfare-url` | `validate_subdomain` locks to single DNS label under `.substack.com`; `validate_loopback_endpoint` restricts inference HTTP calls strictly to loopback interfaces with redirects off |

---

## 3. Automated Scanner & Verification Results (`v0.1.0`)

Executed locally prior to initial release:

- **`cargo fmt --check`**: `exit 0` (clean)
- **`cargo clippy --all-targets --all-features -- -D warnings`**: `exit 0` (`0` warnings, `0` errors)
- **`cargo test --all-targets`**: `10 passed; 0 failed; 0 ignored` in `tests/security_audit.rs` (`0.02s`), covering all 6 threat domains + live Legacy SSE (`/sse` + `/message`) + live MCP 2.0 Streamable HTTP (`/mcp`) roundtrips.
- **`cargo audit`**: Scanned `Cargo.lock` (`271` crate dependencies against `1568` RustSec advisories) -> **`0` security vulnerabilities**; `1` informational unmaintained notice (`RUSTSEC-2026-0543` on transitive `chrono 0.4.45` required by `rmcp 3.11.0`, documented in `deny.toml` with zero known CVEs).
- **`cargo deny check`**: **`advisories ok, bans ok, licenses ok, sources ok`** (`openssl` & `openssl-sys` verified absent).
- **`gitleaks detect --source . --no-git --verbose`**: **`0` leaks found** across `150.70 MB` scanned.
- **`xmllint --noout assets/architecture.svg`**: `exit 0`.
