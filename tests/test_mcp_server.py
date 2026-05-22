"""Test MCP server initialization and tool registration."""
import pytest
from mcp_server import SentinelMCPServer


def test_mcp_server_initializes():
    """Should initialize without errors."""
    server = SentinelMCPServer()
    assert server is not None


def test_mcp_server_has_registered_tools():
    """Should have three tools registered."""
    server = SentinelMCPServer()
    tools = server.get_tools()
    assert len(tools) == 3
    tool_names = [t["name"] for t in tools]
    assert "query_cloudtrail" in tool_names
    assert "get_iam_policy" in tool_names
    assert "quarantine_principal" in tool_names


def test_mcp_server_tool_schemas_valid():
    """Each tool should have valid schema with name and description."""
    server = SentinelMCPServer()
    tools = server.get_tools()
    for tool in tools:
        assert "name" in tool
        assert "description" in tool
        assert isinstance(tool["name"], str)
        assert len(tool["name"]) > 0
