# SessionArmor MCP server

This directory holds SessionArmor's public agent contract and a launcher for
the packaged stdio MCP server. Agents can use it to discover SessionArmor's
middleware, settings, and extension points, and to get guidance for security
settings, gates, and rollout plans. The server runs locally under the caller's
control, makes no network connections, and needs no credentials or account.
There is no hosted SessionArmor MCP service, and nothing here gives access to
the owner's agents, accounts, or infrastructure.

## Run

After installing SessionArmor:

```bash
sessionarmor-mcp
python -m session_armor.mcp     # the same server
```

From a source checkout:

```bash
python mcp/server.py
```

## Files

| File | Purpose |
| --- | --- |
| `README.md` | This guide. |
| `agent-contract.json` | The public agent contract, byte-identical to the packaged `src/session_armor/mcp/agent-contract.json`. |
| `server.py` | Runs the packaged server, `session_armor.mcp.server`, from a source checkout. |

## Methods and tools

The server implements `initialize`, `ping`, `resources/list`,
`resources/read`, `tools/list`, `tools/call`, `prompts/list`, and
`prompts/get`.

Every tool returns the contract's guidance for its task, with the arguments
you passed and the contract's access and safety rules. The calling agent
writes any settings or gate code, for a person to review.

| Tool | Guidance on |
| --- | --- |
| `describe_offering` | SessionArmor's middleware, settings, extension points, and safe operating model. |
| `list_public_capabilities` | Package APIs, settings, extension points, docs, and security references. |
| `map_workflow_to_tools` | Mapping a goal to public APIs, settings, approvals, and verification steps. |
| `prepare_security_configuration` | A reviewed settings plan for timeouts, fingerprint binding, proxy trust, and claim drift. |
| `draft_gate_middleware` | A typed, fail-closed `GateMiddleware` subclass with identity-bound caching and rejection handling. |
| `operate_browser_docs` | Walking a user through public docs, PyPI, GitHub issues, or security references in a browser. |

Resources: `overview`, `public-apis`, `workflows`, `browser-surfaces`, and
`security-and-audit`. Prompt: `agent_onboarding`.

## Limits

The server reads one JSON-RPC message per line. It answers with a JSON-RPC
error, and keeps serving, when a line is longer than 1,100,000 characters
(newline included), is not valid UTF-8 JSON, repeats an object key, uses `NaN`
or `Infinity`, has a number longer than 256 characters, or has an invalid
request shape.

## Boundaries

- SessionArmor controls security-sensitive middleware, so the contract is
  review-first: a person approves every production change.
- Agents must not depend on raw session data, cookies, personal audit data,
  or private application code unless the user supplies a safe, redacted
  sample.
- Agents work from published package APIs, public documentation, and this
  contract. They must not assume access to private source code, unredacted
  settings, production data, or provider dashboards unless the user grants
  it.
