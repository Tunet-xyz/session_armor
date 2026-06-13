from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
CONTRACT_PATH = Path(__file__).with_name("agent-contract.json")


def load_contract() -> dict[str, Any]:
    with CONTRACT_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def write_message(message: dict[str, Any]) -> None:
    sys.stdout.write(compact_json(message) + "\n")
    sys.stdout.flush()


def result(request_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def error(request_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        body["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": body}


def list_resources(contract: dict[str, Any]) -> dict[str, Any]:
    offering_id = contract["offering"]["id"]
    resources = [
        {
            "uri": f"opensource://{offering_id}/agent-contract",
            "name": "agent-contract",
            "title": "Full Agent Contract",
            "description": "The complete public MCP operating contract for this open-source offering.",
            "mimeType": "application/json",
        }
    ]
    for resource in contract.get("resources", []):
        resources.append(
            {
                "uri": resource["uri"],
                "name": resource.get("name", resource["uri"].rsplit("/", 1)[-1]),
                "title": resource.get("title", resource.get("name", resource["uri"])),
                "description": resource.get("description", ""),
                "mimeType": resource.get("mimeType", "application/json"),
            }
        )
    return {"resources": resources}


def read_resource(contract: dict[str, Any], uri: str) -> dict[str, Any]:
    offering_id = contract["offering"]["id"]
    if uri == f"opensource://{offering_id}/agent-contract":
        return {
            "contents": [
                {"uri": uri, "mimeType": "application/json", "text": pretty_json(contract)}
            ]
        }

    for resource in contract.get("resources", []):
        if resource.get("uri") == uri:
            text = resource.get("content")
            if text is None:
                text = pretty_json(resource.get("data", resource))
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": resource.get("mimeType", "application/json"),
                        "text": text if isinstance(text, str) else pretty_json(text),
                    }
                ]
            }
    raise KeyError(uri)


def list_tools(contract: dict[str, Any]) -> dict[str, Any]:
    tools = []
    for tool in contract.get("tools", []):
        tools.append(
            {
                "name": tool["name"],
                "title": tool.get("title", tool["name"].replace("_", " ").title()),
                "description": tool.get("description", ""),
                "inputSchema": tool.get("inputSchema", {"type": "object", "properties": {}}),
                "outputSchema": tool.get("outputSchema"),
                "annotations": tool.get("annotations", {}),
            }
        )
    return {"tools": tools}


def call_tool(contract: dict[str, Any], name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    for tool in contract.get("tools", []):
        if tool.get("name") == name:
            structured = {
                "offering": contract["offering"],
                "tool": tool,
                "arguments": arguments,
                "executionMode": tool.get("executionMode", "contract"),
                "access": contract.get("publicAccess", {}),
                "security": contract.get("security", {}),
            }
            text = (
                f"{tool.get('title', name)} is available for {contract['offering']['name']}.\n\n"
                f"Execution mode: {structured['executionMode']}\n"
                f"Purpose: {tool.get('description', '')}\n\n"
                "Use the structured content to map the request to public docs, package APIs, "
                "MCP tools, CLI commands, browser-visible docs, safety rules, and verification steps."
            )
            return {
                "content": [{"type": "text", "text": text}],
                "structuredContent": structured,
                "isError": False,
            }
    raise KeyError(name)


def list_prompts(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "prompts": [
            {
                "name": prompt["name"],
                "title": prompt.get("title", prompt["name"].replace("_", " ").title()),
                "description": prompt.get("description", ""),
                "arguments": prompt.get("arguments", []),
            }
            for prompt in contract.get("prompts", [])
        ]
    }


def get_prompt(contract: dict[str, Any], name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    for prompt in contract.get("prompts", []):
        if prompt.get("name") == name:
            text = prompt.get("template", "")
            for key, value in arguments.items():
                text = text.replace("{" + key + "}", str(value))
            return {
                "description": prompt.get("description", ""),
                "messages": [
                    {"role": "user", "content": {"type": "text", "text": text}}
                ],
            }
    raise KeyError(name)


def handle(message: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}

    if request_id is None:
        return None

    try:
        if method == "initialize":
            return result(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {
                        "resources": {"listChanged": False},
                        "tools": {"listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": contract["server"]["name"],
                        "title": contract["server"].get("title", contract["offering"]["name"]),
                        "version": contract["server"].get("version", "0.1.0"),
                    },
                    "instructions": contract.get("instructions", ""),
                },
            )
        if method == "resources/list":
            return result(request_id, list_resources(contract))
        if method == "resources/read":
            return result(request_id, read_resource(contract, params["uri"]))
        if method == "tools/list":
            return result(request_id, list_tools(contract))
        if method == "tools/call":
            return result(request_id, call_tool(contract, params["name"], params.get("arguments") or {}))
        if method == "prompts/list":
            return result(request_id, list_prompts(contract))
        if method == "prompts/get":
            return result(request_id, get_prompt(contract, params["name"], params.get("arguments") or {}))
        return error(request_id, -32601, f"Method not found: {method}")
    except KeyError as exc:
        return error(request_id, -32602, f"Unknown or invalid parameter: {exc}")
    except Exception as exc:  # pragma: no cover - defensive protocol boundary
        return error(request_id, -32603, "Internal error", {"detail": str(exc)})


def main() -> None:
    contract = load_contract()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            write_message(error(None, -32700, "Parse error", {"detail": str(exc)}))
            continue
        response = handle(message, contract)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    main()
