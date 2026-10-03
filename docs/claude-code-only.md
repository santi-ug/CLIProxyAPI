# Claude Code subscription routing

Set `claude-code-only: true` or `server.claude-code-only: true` in config v8 to reserve Claude subscription logins for native Claude Code Messages and token-count requests.

Codex, OpenCode, OpenAI-compatible requests, and unrecognized Messages clients cannot use those logins. If a Claude API key also serves the requested model, it remains available. A model served only by subscription logins is hidden from other client model lists. Rejected requests return HTTP 403 without cooling a credential.

The server checks the existing native Claude Code headers and Messages identity signals before selection. The executor checks them again and requires the Claude request format. It refuses unrecognized subscription requests before request cloaking. This identifies the supported wire format, not a cryptographic client attestation. A client that copies every native signal could imitate it.

The default is false and config reload applies the policy. This policy is server-wide in the embeddable SDK process.
