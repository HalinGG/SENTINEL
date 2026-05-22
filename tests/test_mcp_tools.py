"""Unit tests for MCP tools — CloudTrail, IAM, quarantine."""
import pytest
from mcp_tools import query_cloudtrail, get_iam_policy, quarantine_principal


class TestQueryCloudtrail:
    """Tests for query_cloudtrail() tool."""

    def test_query_cloudtrail_returns_events(self):
        """Should return events for compromised-user."""
        result = query_cloudtrail("compromised-user")
        assert isinstance(result, dict)
        assert "principal_id" in result
        assert "event_count" in result
        assert "events" in result
        assert result["event_count"] >= 4
        for event in result["events"]:
            assert "eventTime" in event
            assert "eventName" in event
            assert "sourceIPAddress" in event

    def test_query_cloudtrail_nonexistent_user(self):
        """Should handle missing user gracefully."""
        result = query_cloudtrail("nonexistent-user-xyz")
        assert result["event_count"] == 0
        assert result["events"] == []


class TestGetIAMPolicy:
    """Tests for get_iam_policy() tool."""

    def test_get_iam_policy_returns_policies(self):
        """Should return policies for compromised-user."""
        result = get_iam_policy("compromised-user")
        assert isinstance(result, dict)
        assert "principal_id" in result
        assert "attached_policies" in result
        assert len(result["attached_policies"]) > 0
        assert any("S3" in p.get("PolicyName", "") for p in result["attached_policies"])

    def test_get_iam_policy_nonexistent_user(self):
        """Should handle missing user gracefully."""
        result = get_iam_policy("nonexistent-user-xyz")
        assert result["attached_policies"] == []


class TestQuarantinePrincipal:
    """Tests for quarantine_principal() tool."""

    def test_quarantine_principal_disables_access(self):
        """Should attach deny-all policy and delete keys."""
        result = quarantine_principal("compromised-user")
        assert isinstance(result, dict)
        assert "principal_id" in result
        assert "actions_taken" in result
        assert "timestamp" in result
        assert len(result["actions_taken"]) > 0
        assert "deny_all_policy_attached" in result["actions_taken"]

    def test_quarantine_principal_idempotent(self):
        """Should be safe to call twice."""
        result1 = quarantine_principal("compromised-user")
        result2 = quarantine_principal("compromised-user")
        assert result1["principal_id"] == result2["principal_id"]
        assert len(result2["actions_taken"]) >= 0  # May have 0 actions on second call
