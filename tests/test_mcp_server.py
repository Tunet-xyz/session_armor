from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from session_armor.mcp import server
from session_armor.mcp.server import handle, load_contract, parse_message

ROOT = Path(__file__).resolve().parents[1]


def test_repository_and_packaged_contracts_are_identical() -> None:
    repository_contract = json.loads((ROOT / "mcp" / "agent-contract.json").read_text())

    assert repository_contract == load_contract()


def test_contract_lists_every_setting_the_package_reads() -> None:
    source = "".join(
        path.read_text() for path in sorted((ROOT / "src" / "session_armor").rglob("*.py"))
    )
    public_apis = next(
        resource
        for resource in load_contract()["resources"]
        if resource["name"] == "public-apis"
    )

    assert set(public_apis["data"]["settings"]) == set(
        re.findall(r'"(SESSION_ARMOR_[A-Z_]+)"', source)
    )


def test_initialize_reports_release_version() -> None:
    response = handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"}, load_contract()
    )
    assert response is not None
    assert response["result"]["serverInfo"]["version"] == "0.6.0"


@pytest.mark.parametrize(
    "document",
    [
        '{"jsonrpc":"2.0","jsonrpc":"2.0"}',
        '{"jsonrpc":"2.0","id":1e999}',
        '{"jsonrpc":"2.0","id":NaN}',
    ],
)
def test_parser_rejects_ambiguous_or_non_finite_json(document: str) -> None:
    with pytest.raises(ValueError):
        parse_message(document)


def test_protocol_validation_rejects_invalid_shapes() -> None:
    contract = load_contract()
    assert handle([], contract)["error"]["code"] == -32600
    assert handle({"jsonrpc": "1.0", "id": 1, "method": "x"}, contract)["error"][
        "code"
    ] == -32600
    assert handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []},
        contract,
    )["error"]["code"] == -32602


def test_notifications_never_produce_a_response() -> None:
    assert handle({"jsonrpc": "2.0", "method": "resources/list"}, load_contract()) is None


def test_tool_arguments_must_be_a_mapping() -> None:
    response = handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "describe_offering", "arguments": []},
        },
        load_contract(),
    )
    assert response["error"]["code"] == -32602


def test_resources_tools_and_prompts_are_operable() -> None:
    contract = load_contract()
    resources = handle({"jsonrpc": "2.0", "id": 1, "method": "resources/list"}, contract)
    assert resources["result"]["resources"]
    uri = resources["result"]["resources"][0]["uri"]
    read = handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {"uri": uri},
        },
        contract,
    )
    assert "SessionArmor" in read["result"]["contents"][0]["text"]

    tools = handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, contract)
    tool_name = tools["result"]["tools"][0]["name"]
    called = handle(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": {}},
        },
        contract,
    )
    assert called["result"]["isError"] is False

    prompts = handle({"jsonrpc": "2.0", "id": 5, "method": "prompts/list"}, contract)
    prompt = prompts["result"]["prompts"][0]
    arguments = {item["name"]: "test goal" for item in prompt.get("arguments", [])}
    rendered = handle(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "prompts/get",
            "params": {"name": prompt["name"], "arguments": arguments},
        },
        contract,
    )
    assert rendered["result"]["messages"]


def test_unknown_names_and_bad_resource_types_are_invalid_params() -> None:
    contract = load_contract()
    for message in (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": 7},
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "prompts/get",
            "params": {"name": "unknown"},
        },
    ):
        assert handle(message, contract)["error"]["code"] == -32602


def test_unknown_method_is_reported() -> None:
    response = handle(
        {"jsonrpc": "2.0", "id": 1, "method": "invented"}, load_contract()
    )
    assert response["error"]["code"] == -32601


def test_main_processes_valid_and_invalid_lines(monkeypatch) -> None:
    stdin = io.StringIO(
        "not json\n" + '{"jsonrpc":"2.0","id":1,"method":"resources/list"}\n'
    )
    stdout = io.StringIO()
    monkeypatch.setattr(server.sys, "stdin", stdin)
    monkeypatch.setattr(server.sys, "stdout", stdout)

    server.main()

    lines = stdout.getvalue().splitlines()
    assert '"code":-32700' in lines[0]
    assert '"result"' in lines[1]


def test_parser_enforces_message_and_integer_limits() -> None:
    with pytest.raises(ValueError, match="size limit"):
        parse_message(" " * (server.MAX_MESSAGE_CHARS + 1))
    with pytest.raises(ValueError, match="digit limit"):
        parse_message("1" * (server.MAX_JSON_NUMBER_CHARS + 1))


def test_stdio_output_is_ascii_and_survives_lone_surrogates(monkeypatch, capsys) -> None:
    lines = [
        '{"jsonrpc":"2.0","id":"\\ud83d","method":"tools/list"}',
        '{"jsonrpc":"2.0","id":2,"method":"x\\udc00"}',
        '{"jsonrpc":"2.0","id":3,"method":"initialize"}',
    ]
    monkeypatch.setattr(server.sys, "stdin", io.StringIO("\n".join(lines) + "\n"))

    server.main()

    output = capsys.readouterr().out
    assert output.isascii()
    responses = [json.loads(line) for line in output.splitlines()]
    assert responses[0]["id"] == "\ud83d"
    assert responses[1]["error"]["message"] == "Method not found: x\udc00"
    assert responses[2]["result"]["serverInfo"]["version"] == "0.6.0"


def test_unserializable_response_becomes_an_internal_error(capsys) -> None:
    deep: list[object] = []
    for _ in range(100_000):
        deep = [deep]

    server.write_message({"jsonrpc": "2.0", "id": 5, "result": {"value": deep}})
    server.write_message({"jsonrpc": "2.0", "id": [deep], "error": {"code": -32600}})

    first, second = (json.loads(line) for line in capsys.readouterr().out.splitlines())
    assert first == {
        "jsonrpc": "2.0",
        "id": 5,
        "error": {"code": -32603, "message": "Internal error"},
    }
    assert second["id"] is None
    assert second["error"]["code"] == -32603


def test_stdio_server_decodes_utf8_whatever_the_locale_encoding() -> None:
    root = Path(__file__).resolve().parents[1]
    lines = [
        b'{"jsonrpc":"2.0","id":1,"method":"\xff"}',
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "describe_offering", "arguments": {"goal": "\u00c1bel \u2192 \u691c\u8a3c"}},
            },
            ensure_ascii=False,
        ).encode("utf-8"),
        b'{"jsonrpc":"2.0","id":3,"method":"initialize"}',
    ]
    for encoding in ("utf-8:strict", "cp1252"):
        completed = subprocess.run(
            [sys.executable, str(root / "mcp" / "server.py")],
            cwd=root,
            input=b"\n".join(lines) + b"\n",
            capture_output=True,
            env={**os.environ, "PYTHONIOENCODING": encoding},
            check=True,
            timeout=20,
        )
        responses = [json.loads(line.decode("utf-8")) for line in completed.stdout.splitlines()]

        assert responses[0]["error"]["code"] == -32700
        assert responses[0]["error"]["data"]["detail"] == "MCP messages must be valid UTF-8."
        assert responses[1]["result"]["structuredContent"]["arguments"] == {"goal": "\u00c1bel \u2192 \u691c\u8a3c"}
        assert responses[2]["result"]["serverInfo"]["version"] == "0.6.0"


def test_parser_rejects_text_that_is_not_utf8() -> None:
    with pytest.raises(ValueError, match="valid UTF-8"):
        parse_message('{"jsonrpc":"2.0","id":1,"method":"\udcff"}')


def test_tool_list_and_ping_follow_the_mcp_schema() -> None:
    contract = load_contract()
    tools = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, contract)
    ping = handle({"jsonrpc": "2.0", "id": 2, "method": "ping"}, contract)
    null_id = handle({"jsonrpc": "2.0", "id": None, "method": "tools/list"}, contract)

    for tool in tools["result"]["tools"]:
        assert all(value is not None for value in tool.values())
        assert isinstance(tool.get("outputSchema", {}), dict)
    assert ping == {"jsonrpc": "2.0", "id": 2, "result": {}}
    assert null_id["error"]["code"] == -32600


def test_invalid_request_ids_are_never_echoed() -> None:
    response = handle(
        {"jsonrpc": "1.0", "id": {"nested": [1, 2, {"x": "y"}]}, "method": "tools/list"},
        load_contract(),
    )

    assert response == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": "Invalid Request"},
    }
