SENTINEL is an autonomous SOC triage agent built with Python, MCP (Model Context Protocol), LocalStack, and Claude AI.

The README should include these sections:

1. Title + badges (Python version, License, Tests passing)

2. Overview (2-3 paragraphs):
   - What SENTINEL is: autonomous security analyst that triages GuardDuty-style findings
   - What problem it solves: SOC analysts are overwhelmed with alerts, SENTINEL automates the triage decision
   - Key achievement: demonstrates agentic AI security workflows with real threat intel feeds, MCP tools, and chain-of-thought reasoning

3. Architecture diagram (ASCII art) showing:
   GuardDuty Finding → SentinelAgent → [MCP Tools: CloudTrail, IAM, Quarantine] → Claude API (chain-of-thought) → Decision (QUARANTINE/MONITOR)
   Also show: AbuseIPDB + AlienVault OTX feeding into threat intel
   And: LocalStack emulating AWS IAM + S3 CloudTrail

4. Features:
   - Autonomous triage: analyzes findings without human intervention
   - Chain-of-thought reasoning: Claude reasons step-by-step before deciding
   - MCP server: exposes AWS tools via Model Context Protocol
   - Threat intel integration: AbuseIPDB + AlienVault OTX via GCP Secret Manager
   - Prompt injection resistance: red team tested against 3 attack vectors
   - FedRAMP-aligned security: secrets management, least privilege, audit logging
   - Full test suite: 13+ pytest tests covering all components

5. Security controls implemented:
   - NIST SP 800-53 SC-7 (Boundary Protection)
   - NIST SP 800-53 AC-3 (Access Enforcement)
   - NIST SP 800-53 SI-7 (Software Integrity)
   - CIS Controls v8 12.1 (Network Segmentation)
   - OWASP LLM Top 10: LLM01 (Prompt Injection resistance tested)

6. Project structure (tree format):
sentinel/
  agent.py          # Autonomous triage agent
  main.py           # Threat intel aggregator entry point
  config.py         # Configuration constants
  mcp_server.py     # MCP server with tool registration
  mcp_tools.py      # CloudTrail, IAM, quarantine tool functions
  red_team.py       # Prompt injection attack functions
  seed_localstack.py # LocalStack AWS IR scenario seed data
  docker-compose.yml # LocalStack container setup
  feeds/
    abuseipdb.py    # AbuseIPDB threat intel feed
    alien.py        # AlienVault OTX threat intel feed
  tests/
    test_mcp_tools.py    # 6 tests: CloudTrail, IAM, quarantine tools
    test_mcp_server.py   # 3 tests: MCP server initialization
    test_agent.py        # 4 tests: autonomous triage decisions
    test_red_team.py     # 3 tests: prompt injection resistance

7. Prerequisites:
   - GCP account with Secret Manager enabled
   - Docker installed
   - Python 3.12+ (tested on 3.14)
   - Anthropic API key
   - AbuseIPDB API key (free tier: 1000/day)
   - AlienVault OTX API key (free)

8. Setup instructions (step by step):
   Step 1: Clone the repo
   Step 2: Store API keys in GCP Secret Manager (exact commands with secret names)
   Step 3: Start LocalStack: sudo docker compose up -d
   Step 4: Create Python venv and install requirements
   Step 5: Seed LocalStack with IR scenario: python3 seed_localstack.py
   Step 6: Run all tests: python3 -m pytest tests/ -v
   Step 7: Run the agent: python3 agent.py

9. Example output (show what a QUARANTINE decision looks like as formatted JSON):
{
  "principal_id": "compromised-user",
  "action": "QUARANTINE",
  "reasoning": "...",
  "severity": 8.0,
  "cloudtrail_events": 4,
  "iam_policies": ["AmazonS3FullAccess"],
  "timestamp": "2026-05-22T04:59:00Z"
}

10. Attack scenario (brief):
   - Explain the simulated attack: ListBucket → GetObject → PutObject → PutBucketEncryption
   - Explain why SENTINEL detects it: activity pattern + severity + GuardDuty finding type
   - Explain prompt injection resistance: agent prioritizes GuardDuty signals over retrieved data

11. Red team findings:
   - Attack vector 1: Injected instructions in AbuseIPDB threat intel feed → RESISTED
   - Attack vector 2: Malicious CloudTrail event data injection → RESISTED
   - Attack vector 3: Poisoned IAM policy descriptions → RESISTED

12. Future improvements:
   - LangFuse tracing for production observability
   - Real AWS GuardDuty integration
   - Slack/PagerDuty alerting on QUARANTINE decisions
   - MITRE ATT&CK mapping for detected patterns
   - Multi-account AWS support

13. Author:
   Halin Gordon — Security Engineer
   LinkedIn: [add your LinkedIn]
   Built to demonstrate AI-native security engineering for autonomous SOC operations.

Format requirements:
- Use proper markdown with headers, code blocks, and tables
- ASCII architecture diagram should be clear and readable
- Setup commands should be in bash code blocks
- Keep it professional but readable — not overly corporate
- Include a note that this is a portfolio/demonstration project

Show me the complete README.md content.
