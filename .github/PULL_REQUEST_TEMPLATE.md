## Summary

- What does this PR change and why?

## Security & Verification Checklist

- [ ] `#![forbid(unsafe_code)]` preserved (zero `unsafe`, zero `.unwrap()`, zero OpenSSL)
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --all-targets` (including `tests/security_audit.rs`) passes
- [ ] `cargo audit` & `cargo deny check` pass with 0 advisories
- [ ] `gitleaks detect --source . --verbose` finds 0 leaks
