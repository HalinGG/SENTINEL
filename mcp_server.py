"""MCP (Model Context Protocol) server wrapping security operations tools."""

import logging
from typing import Any, Dict, List

from mcp_tools import get_iam_policy, query_cloudtrail, quarantine_principal

logger = logging.getLogger(__name__)


class SentinelMCPServer:
    """MCP server for Sentinel security operations tools.

    Registers and manages access to CloudTrail query, IAM policy inspection,
    and principal quarantine tools via the Model Context Protocol.
    """

    def __init__(self) -> None:
        """Initialize the MCP server and register available tools."""
        logger.info("Initializing SentinelMCPServer")

        self._tools: List[Dict[str, Any]] = []

        try:
            self._register_tools()
            logger.info(f"Successfully registered {len(self._tools)} tools")
        except Exception as e:
            logger.error(f"Error initializing MCP server: {e}")
            raise

    def _register_tools(self) -> None:
        """Register all available security operations tools."""
        principal_id_schema = {
            "type": "object",
            "properties": {
                "principal_id": {
                    "type": "string",
                    "description": "The AWS principal/user name (e.g., 'compromised-user')",
                }
            },
            "required": ["principal_id"],
        }

        self._tools = [
            {
                "name": "query_cloudtrail",
                "description": "Query CloudTrail events for a specific AWS principal. "
                "Searches all CloudTrail logs in S3, filters by principal name, and returns "
                "events with timestamps, event names, and source IP addresses.",
                "inputSchema": principal_id_schema,
            },
            {
                "name": "get_iam_policy",
                "description": "Retrieve IAM policies attached to a specific user. "
                "Lists all managed and inline policies directly attached to the user. "
                "Returns gracefully if the user does not exist.",
                "inputSchema": principal_id_schema,
            },
            {
                "name": "quarantine_principal",
                "description": "Quarantine a principal by disabling all access. "
                "Deletes all access keys and attaches a deny-all inline policy. "
                "Safe to call multiple times (idempotent operation).",
                "inputSchema": principal_id_schema,
            },
        ]

        logger.debug(f"Registered tools: {[t['name'] for t in self._tools]}")

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get list of registered tool schemas.

        Returns:
            List of tool definitions, each with name, description, and inputSchema.
        """
        return self._tools
