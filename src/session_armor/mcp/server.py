from __future__ import annotations

import json
import math
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

PROTOCOL_VERSION = "2025-06-18"
CONTRACT_PATH = Path(__file__).with_name("agent-contract.json")
MAX_MESSAGE_CHARS = 1_100_000
MAX_JSON_NUMBER_CHARS = 256


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Unsupported JSON constant: {value}")


def _reject_duplicate_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON object key: {key}")
        value[key] = item
    return value


def _parse_json_integer(value: str) -> int:
    if len(value) > MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON integer exceeds the digit limit.")
    return int(value)


def _parse_json_float(value: str) -> float:
    if len(value) > MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON number exceeds the digit limit.")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON numbers must be finite.")
    return number


def parse_message(document: str) -> object:
    if not isinstance(document, str):
        raise TypeError("MCP messages must be strings.")
    if len(document) > MAX_MESSAGE_CHARS:
        raise ValueError("MCP message exceeds the size limit.")
    return json.loads(
        document,
        parse_constant=_reject_json_constant,
        parse_float=_parse_json_float,
        parse_int=_parse_json_integer,
        object_pairs_hook=_reject_duplicate_json_object,
    )


def load_contract() -> dict[str, Any]:
    with CONTRACT_PATH.open("r", encoding="utf-8") as handle:
        return cast(dict[str, Any], json.load(handle))


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
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
            }
    raise KeyError(name)


def handle(message: object, contract: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(message, Mapping):
        return error(None, -32600, "Invalid Request")
    is_notification = "id" not in message
    request_id = message.get("id")
    method = message.get("method")
    if message.get("jsonrpc") != "2.0":
        return None if is_notification else error(request_id, -32600, "Invalid Request")
    if not is_notification and (
        isinstance(request_id, bool) or not isinstance(request_id, str | int | type(None))
    ):
        return error(None, -32600, "Invalid Request")
    if not isinstance(method, str) or not method:
        return None if is_notification else error(request_id, -32600, "Invalid Request")
    raw_params = message.get("params", {})
    if raw_params is None:
        raw_params = {}
    if not isinstance(raw_params, Mapping):
        return None if is_notification else error(request_id, -32602, "Invalid params")
    params = cast(Mapping[str, Any], raw_params)

    try:
        if method == "initialize":
            response = result(
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
                        "version": contract["server"].get("version", "0.4.0"),
                    },
                    "instructions": contract.get("instructions", ""),
                },
            )
        elif method == "resources/list":
            response = result(request_id, list_resources(contract))
        elif method == "resources/read":
            uri = params["uri"]
            if not isinstance(uri, str):
                raise TypeError("uri must be a string")
            response = result(request_id, read_resource(contract, uri))
        elif method == "tools/list":
            response = result(request_id, list_tools(contract))
        elif method == "tools/call":
            name = params["name"]
            arguments = params.get("arguments", {})
            if arguments is None:
                arguments = {}
            if not isinstance(name, str) or not isinstance(arguments, Mapping):
                raise TypeError("tool name and arguments have invalid types")
            response = result(request_id, call_tool(contract, name, dict(arguments)))
        elif method == "prompts/list":
            response = result(request_id, list_prompts(contract))
        elif method == "prompts/get":
            name = params["name"]
            arguments = params.get("arguments", {})
            if arguments is None:
                arguments = {}
            if not isinstance(name, str) or not isinstance(arguments, Mapping):
                raise TypeError("prompt name and arguments have invalid types")
            response = result(request_id, get_prompt(contract, name, dict(arguments)))
        else:
            response = error(request_id, -32601, f"Method not found: {method}")
    except (KeyError, TypeError, ValueError) as exc:
        response = error(request_id, -32602, f"Unknown or invalid parameter: {exc}")
    except Exception as exc:  # pragma: no cover - defensive protocol boundary
        response = error(request_id, -32603, "Internal error", {"detail": type(exc).__name__})
    return None if is_notification else response


def main() -> None:
    contract = load_contract()
    while True:
        line = sys.stdin.readline(MAX_MESSAGE_CHARS + 1)
        if not line:
            break
        if len(line) > MAX_MESSAGE_CHARS:
            while line and not line.endswith("\n"):
                line = sys.stdin.readline(MAX_MESSAGE_CHARS + 1)
            write_message(error(None, -32700, "Message exceeds the size limit"))
            continue
        if not line.strip():
            continue
        try:
            message = parse_message(line)
        except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
            write_message(error(None, -32700, "Parse error", {"detail": str(exc)}))
            continue
        response = handle(message, contract)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    main()
