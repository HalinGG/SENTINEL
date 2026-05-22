#!/usr/bin/env bash
# Phase 2 Setup — FedRAMP Audit Evidence Script
set -x

AUDIT_LOG="$HOME/sentinel/audit.log"

TIMESTAMP() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Audit wrapper: captures label, full command, stdout, stderr, exit code, duration
audit_run() {
    local label="$1"; shift
    local stdout_file stderr_file rc time_start time_end duration ts_start ts_end

    ts_start=$(TIMESTAMP)
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)
    time_start=$(date +%s%3N)

    "$@" >"$stdout_file" 2>"$stderr_file"
    rc=$?

    time_end=$(date +%s%3N)
    ts_end=$(TIMESTAMP)
    duration=$(( time_end - time_start ))

    {
        printf '\n================================================================================\n'
        printf 'AUDIT ENTRY\n'
        printf '  Label     : %s\n' "$label"
        printf '  Command   : %s\n' "$*"
        printf '  Started   : %s\n' "$ts_start"
        printf '  Finished  : %s\n' "$ts_end"
        printf '  Duration  : %sms\n' "$duration"
        printf '  Exit Code : %s\n' "$rc"
        printf '  User      : %s\n' "$(whoami)"
        printf '  Host      : %s\n' "$(hostname)"
        printf '--- STDOUT ---\n'
        cat "$stdout_file"
        printf '--- STDERR ---\n'
        cat "$stderr_file"
        printf '--- END ENTRY ---\n'
    } | tee -a "$AUDIT_LOG"

    rm -f "$stdout_file" "$stderr_file"
    return $rc
}

# ── Preamble ─────────────────────────────────────────────────────────────────
{
    printf '\n################################################################################\n'
    printf '# SENTINEL PHASE 2 AUDIT LOG\n'
    printf '# FedRAMP Compliance Evidence\n'
    printf '# PHASE 2 SETUP BEGIN: %s\n' "$(TIMESTAMP)"
    printf '# User      : %s\n' "$(id)"
    printf '# Host      : %s\n' "$(hostname -f 2>/dev/null || hostname)"
    printf '# Working   : %s\n' "$(pwd)"
    printf '################################################################################\n'
} | tee -a "$AUDIT_LOG"

# ── 1. Environment ────────────────────────────────────────────────────────────
audit_run "ENV: whoami"             whoami
audit_run "ENV: id"                 id
audit_run "ENV: uname"              uname -a
audit_run "ENV: python3 version"    python3 --version
audit_run "ENV: pip3 version"       pip3 --version
audit_run "ENV: docker version"     docker --version
audit_run "ENV: docker compose"     docker compose version
audit_run "ENV: localstack cli"     localstack --version
audit_run "ENV: aws cli version"    aws --version
audit_run "ENV: awslocal version"   awslocal --version

# ── 2. pip upgrades ───────────────────────────────────────────────────────────
audit_run "PIP: upgrade localstack"       pip3 install --upgrade localstack
audit_run "PIP: upgrade awscli-local"     pip3 install --upgrade awscli-local
audit_run "PIP: upgrade awscli"           pip3 install --upgrade awscli
audit_run "PIP: list installed packages"  pip3 list --format=columns

# ── 3. Docker state before ────────────────────────────────────────────────────
audit_run "DOCKER: ps -a before"    docker ps -a
audit_run "DOCKER: images"          docker images

# ── 4. Start / restart LocalStack ────────────────────────────────────────────
audit_run "DOCKER: compose down"    docker compose -f "$HOME/sentinel/docker-compose.yml" down --remove-orphans
audit_run "DOCKER: compose up -d"   docker compose -f "$HOME/sentinel/docker-compose.yml" up -d
audit_run "DOCKER: ps -a after"     docker ps -a

# ── 5. Wait for LocalStack health ────────────────────────────────────────────
printf '\n[ %s ] Waiting for LocalStack IAM to become available...\n' "$(TIMESTAMP)" | tee -a "$AUDIT_LOG"

healthy=0
for i in $(seq 1 40); do
    health_body=$(curl -s http://localhost:4566/_localstack/health 2>/dev/null)
    if echo "$health_body" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); assert d.get('services',{}).get('iam') in ('available','running')" \
        2>/dev/null; then
        printf '[ %s ] LocalStack ready after %s polls\n' "$(TIMESTAMP)" "$i" | tee -a "$AUDIT_LOG"
        healthy=1
        break
    fi
    printf '[ %s ] Poll %s/40 — iam not ready\n' "$(TIMESTAMP)" "$i" | tee -a "$AUDIT_LOG"
    sleep 3
done

if [ "$healthy" -ne 1 ]; then
    printf '[ %s ] ERROR: LocalStack did not become healthy\n' "$(TIMESTAMP)" | tee -a "$AUDIT_LOG"
    audit_run "DOCKER: localstack logs (failure)" docker logs localstack
    exit 1
fi

audit_run "LOCALSTACK: health endpoint"     bash -c 'curl -s http://localhost:4566/_localstack/health | python3 -m json.tool'
audit_run "DOCKER: localstack logs (start)" docker logs localstack

# ── 6. AWS credentials ────────────────────────────────────────────────────────
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

printf '\n[ %s ] AWS_ACCESS_KEY_ID=test  AWS_DEFAULT_REGION=us-east-1\n' "$(TIMESTAMP)" | tee -a "$AUDIT_LOG"

# ── 7. IAM setup ──────────────────────────────────────────────────────────────
audit_run "IAM: list-users (baseline)"  awslocal iam list-users

cat > /tmp/sentinel-trust-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "cloudtrail.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
POLICY

cat > /tmp/sentinel-inline-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "cloudtrail:GetTrailStatus",
      "cloudtrail:DescribeTrails",
      "cloudtrail:LookupEvents",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ],
    "Resource": "*"
  }]
}
POLICY

audit_run "IAM: create-role sentinel-cloudtrail-role" \
    awslocal iam create-role \
        --role-name sentinel-cloudtrail-role \
        --assume-role-policy-document file:///tmp/sentinel-trust-policy.json

audit_run "IAM: put-role-policy sentinel-cloudtrail-policy" \
    awslocal iam put-role-policy \
        --role-name sentinel-cloudtrail-role \
        --policy-name sentinel-cloudtrail-policy \
        --policy-document file:///tmp/sentinel-inline-policy.json

audit_run "IAM: get-role-policy (verify)" \
    awslocal iam get-role-policy \
        --role-name sentinel-cloudtrail-role \
        --policy-name sentinel-cloudtrail-policy

audit_run "IAM: list-roles"         awslocal iam list-roles
audit_run "IAM: list-users (final)" awslocal iam list-users

# ── 8. EventBridge setup ──────────────────────────────────────────────────────
audit_run "EVENTS: list-event-buses (baseline)"  awslocal events list-event-buses

audit_run "EVENTS: create-event-bus sentinel-events" \
    awslocal events create-event-bus --name sentinel-events

audit_run "EVENTS: put-rule sentinel-threat-intel" \
    awslocal events put-rule \
        --name sentinel-threat-intel \
        --event-bus-name sentinel-events \
        --event-pattern '{"source":["sentinel.threat-intel"]}' \
        --state ENABLED \
        --description "Sentinel threat intelligence events"

audit_run "EVENTS: list-rules sentinel-events" \
    awslocal events list-rules --event-bus-name sentinel-events

audit_run "EVENTS: list-event-buses (final)"  awslocal events list-event-buses

# ── 9. Final health + state ───────────────────────────────────────────────────
audit_run "FINAL: localstack health" \
    bash -c 'curl -s http://localhost:4566/_localstack/health | python3 -m json.tool'
audit_run "FINAL: docker ps"         docker ps --filter name=localstack
audit_run "FINAL: iam list-users"    awslocal iam list-users
audit_run "FINAL: iam list-roles"    awslocal iam list-roles
audit_run "FINAL: events list-buses" awslocal events list-event-buses

# ── Done ──────────────────────────────────────────────────────────────────────
{
    printf '\n################################################################################\n'
    printf '# PHASE 2 SETUP COMPLETE: %s\n' "$(TIMESTAMP)"
    printf '# Audit log: %s\n' "$AUDIT_LOG"
    printf '################################################################################\n'
} | tee -a "$AUDIT_LOG"
