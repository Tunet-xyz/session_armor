# Public Agent MCP Contract

This directory defines the public agent-operability contract for this open-source offering. It is written for external user agents that can use published package APIs, hosted or local MCP tools, public documentation, and browser-visible surfaces. It must not assume access to private source code, local repository paths, unredacted settings, production data, or vendor dashboards unless the user explicitly grants that access.

Files:

```text
mcp/
  README.md
  agent-contract.json
  server.py
```

The local stdio server is dependency-free and contract-first. It is useful for development checks and for any MCP client that can launch a local process.

```bash
python mcp/server.py
```

Supported methods:

- `initialize`
- `ping`
- `resources/list`
- `resources/read`
- `tools/list`
- `tools/call`
- `prompts/list`
- `prompts/get`

Production packages may expose richer runtime MCP tools, but those tools should preserve this contract's public-access boundaries, approval gates, and verification expectations.
## SessionArmor Notes

SessionArmor's public contract is review-first because it controls security-sensitive middleware behavior. Agents may generate settings, middleware ordering guidance, custom gate drafts, and rollout plans, but production changes require human approval.

Agents must not depend on raw session data, cookies, personal audit data, or private application code unless the user supplies a safe redacted sample.
