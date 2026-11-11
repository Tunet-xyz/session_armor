from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from session_armor import __version__
from session_armor.mcp import server
from session_armor.mcp.server import handle, load_contract, parse_message

ROOT = Path(__file__).resolve().parents[1]
TOOLS = {tool["name"]: tool for tool in load_contract()["tools"]}
EXAMPLE_VALUES: dict[str, Any] = {"string": "example", "integer": 2, "array": ["example"]}


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
    assert response["result"]["serverInfo"]["version"] == __version__


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
    assert responses[2]["result"]["serverInfo"]["version"] == __version__


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
        assert responses[2]["result"]["serverInfo"]["version"] == __version__


def test_module_entry_point_serves_the_public_contract() -> None:
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    completed = subprocess.run(
        [sys.executable, "-m", "session_armor.mcp"],
        cwd=ROOT,
        input=json.dumps(initialize) + "\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    server_info = json.loads(completed.stdout)["result"]["serverInfo"]

    assert server_info["name"] == "session-armor-public-contract-mcp"
    assert server_info["version"] == __version__


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


def call(method: str, params: dict[str, Any]) -> dict[str, Any]:
    response = handle(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, load_contract()
    )
    assert response is not None
    return response


def valid_arguments(tool: dict[str, Any], *, required_only: bool = False) -> dict[str, Any]:
    """Arguments that satisfy a tool's inputSchema."""
    schema = tool["inputSchema"]
    names = schema.get("required", []) if required_only else list(schema.get("properties", {}))
    arguments: dict[str, Any] = {}
    for name in names:
        spec = schema["properties"][name]
        arguments[name] = spec["enum"][0] if "enum" in spec else EXAMPLE_VALUES[spec["type"]]
    return arguments


@pytest.mark.parametrize("required_only", [False, True])
@pytest.mark.parametrize("name", sorted(TOOLS))
def test_every_tool_accepts_arguments_that_match_its_schema(
    name: str, required_only: bool
) -> None:
    arguments = valid_arguments(TOOLS[name], required_only=required_only)

    reply = call("tools/call", {"name": name, "arguments": arguments})

    assert reply["result"]["isError"] is False
    assert reply["result"]["structuredContent"]["arguments"] == arguments


@pytest.mark.parametrize("depth", [0, 2])
def test_integer_arguments_accept_json_integers(depth: int) -> None:
    arguments = {"riskProfile": "high", "proxyDepth": depth}

    reply = call("tools/call", {"name": "prepare_security_configuration", "arguments": arguments})

    assert reply["result"]["isError"] is False


def test_every_prompt_renders_with_its_declared_arguments() -> None:
    for prompt in load_contract()["prompts"]:
        arguments = {argument["name"]: "test goal" for argument in prompt["arguments"]}

        reply = call("prompts/get", {"name": prompt["name"], "arguments": arguments})

        text = reply["result"]["messages"][0]["content"]["text"]
        assert "test goal" in text
        assert server.PLACEHOLDER.search(text) is None


def test_prompt_arguments_are_substituted_once() -> None:
    template = next(
        prompt["template"]
        for prompt in load_contract()["prompts"]
        if prompt["name"] == "agent_onboarding"
    )
    value = "{user_goal}" * 1000

    reply = call("prompts/get", {"name": "agent_onboarding", "arguments": {"user_goal": value}})

    text = reply["result"]["messages"][0]["content"]["text"]
    assert text.count("{user_goal}") == 1000
    assert len(text) == len(template) - len("{user_goal}") + len(value)


def test_render_prompt_reads_placeholders_from_the_template_only() -> None:
    prompt = {
        "arguments": [{"name": "first", "required": True}, {"name": "second"}, {"name": "third"}],
        "template": "{first} | {second} | {third}",
    }

    text = server.render_prompt(prompt, {"first": "{second}", "second": "{first}"})

    assert text == "{second} | {first} | {third}"


def test_prompt_arguments_cannot_inject_or_amplify() -> None:
    # Filling the template once per argument let one argument's value name another
    # argument, so a request of about 11 KB could produce a reply of megabytes.
    arguments = {"user_goal": "{a}" * 1000, "a": "{b}" * 1000, "b": "x" * 1000}

    reply = call("prompts/get", {"name": "agent_onboarding", "arguments": arguments})

    assert reply["error"]["code"] == -32602
    assert len(json.dumps(reply)) < 1000


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"user_goal": 42},
        {"user_goal": True},
        {"user_goal": None},
        {"user_goal": ["list"]},
        {"user_goal": "a goal", "other": "undeclared"},
    ],
)
def test_prompt_arguments_are_checked(arguments: dict[str, Any]) -> None:
    reply = call("prompts/get", {"name": "agent_onboarding", "arguments": arguments})

    assert reply["error"]["code"] == -32602


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("map_workflow_to_tools", {}),
        ("prepare_security_configuration", {"proxyDepth": 1}),
        ("draft_gate_middleware", {"recheckPolicy": "on every request"}),
        ("operate_browser_docs", {"targetUrl": "https://pypi.org/project/SessionArmor/"}),
        ("list_public_capabilities", {"surface": "everything"}),
        ("list_public_capabilities", {"surface": ["settings"]}),
        ("map_workflow_to_tools", {"workflow": 7}),
        ("prepare_security_configuration", {"riskProfile": None}),
        ("prepare_security_configuration", {"riskProfile": "high", "proxyDepth": "1"}),
        ("prepare_security_configuration", {"riskProfile": "high", "proxyDepth": True}),
        ("prepare_security_configuration", {"riskProfile": "high", "proxyDepth": 1.5}),
        ("prepare_security_configuration", {"riskProfile": "high", "proxyDepth": 2.0}),
        ("draft_gate_middleware", {"gatePurpose": {"goal": "onboarding"}}),
        ("operate_browser_docs", {"task": True}),
    ],
)
def test_tool_arguments_follow_the_input_schema(tool: str, arguments: dict[str, Any]) -> None:
    reply = call("tools/call", {"name": tool, "arguments": arguments})

    assert reply["error"]["code"] == -32602


def test_schema_checks_cover_arrays_booleans_and_untyped_enums() -> None:
    tool = {
        "inputSchema": {
            "type": "object",
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}},
                "strict": {"type": "boolean"},
                "ratio": {"type": "number"},
                "mode": {"enum": ["fast", "safe"]},
            },
        }
    }

    server.check_tool_arguments(
        tool, {"tags": ["a", "b"], "strict": False, "ratio": 0.5, "mode": "safe"}
    )
    for arguments in (
        {"tags": "a"},
        {"tags": ["a", 1]},
        {"strict": 1},
        {"ratio": True},
        {"mode": "slow"},
    ):
        with pytest.raises((TypeError, ValueError)):
            server.check_tool_arguments(tool, arguments)


def test_tool_results_say_they_return_contract_guidance() -> None:
    reply = call("tools/call", {"name": "describe_offering", "arguments": {}})

    assert "does not run SessionArmor or generate code" in reply["result"]["content"][0]["text"]
    for tool in TOOLS.values():
        assert tool["description"].startswith("Return "), tool["name"]
    for name in ("prepare_security_configuration", "draft_gate_middleware"):
        assert TOOLS[name]["description"].startswith("Return the guidance"), name


def test_error_details_are_cut_to_200_characters(monkeypatch, capsys) -> None:
    limit = server.MAX_ERROR_DETAIL_CHARS + len("...")
    for reply in (
        call("tools/call", {"name": "x" * 100_000, "arguments": {}}),
        call("prompts/get", {"name": "agent_onboarding", "arguments": {"y" * 100_000: "z"}}),
    ):
        assert reply["error"]["code"] == -32602
        assert len(reply["error"]["message"]) <= len("Unknown or invalid parameter: ") + limit

    unknown_method = call("m" * 100_000, {})
    assert unknown_method["error"]["code"] == -32601
    assert len(unknown_method["error"]["message"]) <= len("Method not found: ") + limit

    key = "k" * 100_000
    monkeypatch.setattr(server.sys, "stdin", io.StringIO(f'{{"{key}":1,"{key}":2}}\n'))
    server.main()
    parse_error = json.loads(capsys.readouterr().out)
    assert parse_error["error"]["code"] == -32700
    assert len(parse_error["error"]["data"]["detail"]) <= limit
