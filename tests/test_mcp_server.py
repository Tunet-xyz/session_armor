from __future__ import annotations

import io

import pytest

from session_armor.mcp import server
from session_armor.mcp.server import handle, load_contract, parse_message


def test_initialize_reports_release_version() -> None:
    response = handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"}, load_contract()
    )
    assert response is not None
    assert response["result"]["serverInfo"]["version"] == "0.4.0"


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
