# Attribution & Upstream Acknowledgments

`substack-mcp-rs` stands on open-source security-first foundations:

| Component | Upstream Project | License | Role in `substack-mcp-rs` |
|-----------|------------------|---------|---------------------------|
| Local LLM Runtime & `.gturbo` Integrity Contract | [`drumih/turbo-fieldfare`](https://github.com/drumih/turbo-fieldfare) | Apache-2.0 | Inspiration and wire-compatible Rust client for `TurboFieldfareServer` (`/v1/chat/completions`, `127.0.0.1` loopback, temperature `0.2`, Top-P `0.95`) plus full SHA-256 `GTurboManifestV1` + `VerifiedInstallReceipt` verifier |
| MCP 2.0 SDK & Streamable HTTP | [`modelcontextprotocol/rust-sdk`](https://github.com/modelcontextprotocol/rust-sdk) (`rmcp`) | Apache-2.0 | Type-safe `ServerHandler`, `StreamableHttpService`, `StreamableHttpClientTransport`, and `stdio` transports |
| Markdown Pull Parser | [`pulldown-cmark`](https://github.com/pulldown-cmark/pulldown-cmark) | MIT | Single-pass zero-copy CommonMark parser driving the Substack ProseMirror AST compiler |
