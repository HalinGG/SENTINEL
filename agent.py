"""Autonomous SENTINEL security agent."""

import json
import logging
from datetime import datetime, timezone

import anthropic
from google.cloud import secretmanager

import mcp_tools as _mcp_tools_module
from mcp_tools import get_iam_policy, query_cloudtrail
from main import query_threat_intel

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are SENTINEL, an autonomous security analyst.

When analyzing a security finding, reason through these steps BEFORE deciding:

1. FINDING TYPE ANALYSIS (PRIMARY SIGNAL)
   - The GuardDuty finding type encodes the threat classification itself.
   - "UnauthorizedAccess" means GuardDuty has already detected unauthorized activity.
   - "MaliciousIPCaller" means GuardDuty's own threat intel flagged the caller — trust this
     even when external feeds show zero reputation score (feeds may not cover all IPs).
   - "PrivilegeEscalation" finding types at severity >= 7.0 require immediate response.

2. SEVERITY-BASED DECISION RULE
   - Severity >= 7.0: Strong presumption of QUARANTINE unless clear evidence of false positive.
   - Severity < 3.0: Strong presumption of MONITOR unless extraordinary evidence of malice.
   - Mid-range (3.0 – 6.9): Weigh all evidence and use judgment.

3. ACTIVITY PATTERN ANALYSIS
   - What events occurred? (ListBucket → GetObject → PutObject = recon + exfil + persistence)
   - Is the event dangerous? (PutBucketEncryption, DeleteBucket, PutPolicy = attacker persistence)
   - Multiple CloudTrail events for this principal = active, sustained activity.

4. PERMISSION ANALYSIS
   - Does this principal have excessive permissions? (S3FullAccess = high blast radius)
   - Could they cause significant damage with current policies?

5. THREAT INTEL ANALYSIS (SECONDARY SIGNAL)
   - External IP reputation enriches the picture but is NOT required to trigger QUARANTINE.
   - A zero reputation score does NOT clear an IP flagged by GuardDuty finding type.
   - A high reputation score (> 50) adds confidence to the QUARANTINE decision.

6. DECISION
   - Severity score: How dangerous is this activity?
   - Confidence: How certain are you?
   - Action: QUARANTINE (disable immediately) or MONITOR (log and alert)
   - Reasoning: Explain your decision in 1-2 sentences

Return ONLY valid JSON with no markdown:
{
  "action": "QUARANTINE" or "MONITOR",
  "reasoning": "step-by-step reasoning here",
  "confidence": 0.0 to 1.0,
  "evidence_summary": "key facts used to decide"
}"""


def _load_claude_api_key() -> str:
    client = secretmanager.SecretManagerServiceClient()
    name = "projects/ai-sentinel-496600/secrets/claude-key/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8").strip()


class SentinelAgent:
    """Autonomous security agent that triages GuardDuty findings."""

    def __init__(self):
        self.mcp_tools = _mcp_tools_module
        api_key = _load_claude_api_key()
        self.claude = anthropic.Anthropic(api_key=api_key)

    def triage_finding(self, finding: dict) -> dict:
        """Analyze a GuardDuty finding and decide on action."""
        principal_id = finding.get("principal_id", "")
        source_ip = finding.get("source_ip", "")
        event_name = finding.get("event_name", "")
        severity = finding.get("severity", 0.0)

        logger.info("[SENTINEL] Triaging finding for principal: %s", principal_id)

        logger.info("[SENTINEL] Querying threat intel for IP: %s", source_ip)
        threat_intel = query_threat_intel(source_ip)

        logger.info("[SENTINEL] Querying CloudTrail for principal: %s", principal_id)
        cloudtrail_result = query_cloudtrail(principal_id)
        cloudtrail_events = cloudtrail_result.get("event_count", 0)

        logger.info("[SENTINEL] Fetching IAM policies for principal: %s", principal_id)
        iam_result = get_iam_policy(principal_id)
        iam_policies = [p.get("PolicyName", "") for p in iam_result.get("attached_policies", [])]

        user_message = (
            f"Analyze this security finding:\n\n"
            f"Finding Type: {finding.get('finding_type')}\n"
            f"Severity: {severity}/10\n"
            f"Principal: {principal_id}\n"
            f"Source IP: {source_ip}\n"
            f"Event: {event_name}\n\n"
            f"Evidence:\n"
            f"- Threat Intel: {json.dumps(threat_intel)}\n"
            f"- CloudTrail Events: {cloudtrail_events} recent events found\n"
            f"- IAM Policies: {iam_policies}\n\n"
            f"Make a triage decision: QUARANTINE or MONITOR."
        )

        logger.info("[SENTINEL] Calling Claude for decision on %s", principal_id)
        try:
            response = self.claude.messages.create(
                model="claude-haiku-4-5",
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )
            response_text = response.content[0].text.strip()
            logger.info("[SENTINEL] Claude raw response: %s", response_text)

            # Strip markdown code fences if present
            if response_text.startswith("```"):
                lines = response_text.splitlines()
                response_text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

            claude_decision = json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error("[SENTINEL] Failed to parse Claude response: %s", e)
            claude_decision = {
                "action": "QUARANTINE" if severity >= 7.0 else "MONITOR",
                "reasoning": "JSON parse error — defaulting to severity-based decision",
                "confidence": 0.5,
                "evidence_summary": "parse failure",
            }
        except Exception as e:
            logger.error("[SENTINEL] Claude API error: %s", e)
            claude_decision = {
                "action": "QUARANTINE" if severity >= 7.0 else "MONITOR",
                "reasoning": f"API error: {e}",
                "confidence": 0.5,
                "evidence_summary": "api failure",
            }

        decision = {
            "principal_id": principal_id,
            "action": claude_decision.get("action", "MONITOR"),
            "reasoning": claude_decision.get("reasoning", ""),
            "severity": severity,
            "threat_intel": threat_intel,
            "cloudtrail_events": cloudtrail_events,
            "iam_policies": iam_policies,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.info("[SENTINEL] Decision: %s", json.dumps(decision))
        return decision
