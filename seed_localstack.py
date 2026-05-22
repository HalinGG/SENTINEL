"""
Seed LocalStack with realistic IR scenario data for Sentinel testing.

Populates IAM users/roles, an S3 bucket, a CloudTrail trail, and five mock
CloudTrail log events representing a full attacker kill-chain plus one benign
baseline event.
"""

import json
import gzip
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError

ENDPOINT = "http://localhost:4566"
REGION = "us-west-1"
ACCOUNT_ID = "000000000000"  # LocalStack default account ID

SESSION_KWARGS: dict[str, Any] = dict(
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name=REGION,
    endpoint_url=ENDPOINT,
)


def make_client(service: str) -> Any:
    return boto3.client(service, **SESSION_KWARGS)


# ---------------------------------------------------------------------------
# IAM helpers
# ---------------------------------------------------------------------------

def create_iam_user(iam: Any, username: str) -> str:
    """Create an IAM user and return its ARN."""
    try:
        resp = iam.create_user(UserName=username)
        arn = resp["User"]["Arn"]
        print(f"[IAM] Created user '{username}' — ARN: {arn}")
        return arn
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            arn = iam.get_user(UserName=username)["User"]["Arn"]
            print(f"[IAM] User '{username}' already exists — ARN: {arn}")
            return arn
        raise


def create_iam_role(iam: Any, role_name: str) -> str:
    """Create an IAM role with S3FullAccess and return its ARN."""
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    try:
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust_policy,
            Description="Application role for S3 read access",
        )
        role_arn = resp["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
            print(f"[IAM] Role '{role_name}' already exists — ARN: {role_arn}")
        else:
            raise
    else:
        print(f"[IAM] Created role '{role_name}' — ARN: {role_arn}")

    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
        )
        print(f"[IAM] Attached AmazonS3FullAccess to '{role_name}'")
    except ClientError as e:
        print(f"[IAM] Could not attach policy to '{role_name}': {e}")

    return role_arn


# ---------------------------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------------------------

def create_s3_bucket(s3: Any, bucket_name: str) -> None:
    """Create an S3 bucket if it does not already exist."""
    try:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": REGION},
        )
        print(f"[S3]  Created bucket '{bucket_name}'")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            print(f"[S3]  Bucket '{bucket_name}' already exists")
        else:
            raise


# ---------------------------------------------------------------------------
# CloudTrail helpers
# ---------------------------------------------------------------------------

def create_cloudtrail(ct: Any, trail_name: str, bucket_name: str) -> str | None:
    """
    Create a CloudTrail trail logging to *bucket_name*. Returns trail ARN, or
    None if the CloudTrail management API is unavailable (LocalStack Community).
    Events are written directly to S3 in either case.
    """
    try:
        resp = ct.create_trail(Name=trail_name, S3BucketName=bucket_name)
        arn = resp["TrailARN"]
        print(f"[CT]  Created trail '{trail_name}' — ARN: {arn}")
        ct.start_logging(Name=trail_name)
        print(f"[CT]  Started logging for trail '{trail_name}'")
        return arn
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "TrailAlreadyExistsException":
            arn = ct.get_trail(Name=trail_name)["Trail"]["TrailARN"]
            print(f"[CT]  Trail '{trail_name}' already exists — ARN: {arn}")
            return arn
        if code == "InternalFailure":
            print(
                f"[CT]  CloudTrail management API not available in LocalStack Community "
                f"(trail '{trail_name}' skipped). Events will be written directly to S3."
            )
            return None
        raise


# ---------------------------------------------------------------------------
# CloudTrail event builders
# ---------------------------------------------------------------------------

def _event(
    *,
    event_name: str,
    source: str,
    user_type: str,
    username: str,
    user_arn: str,
    source_ip: str,
    resources: list[dict[str, str]],
    request_params: dict[str, Any],
    timestamp: datetime,
) -> dict[str, Any]:
    """Return a single CloudTrail event record."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": user_type,
            "principalId": username,
            "arn": user_arn,
            "accountId": ACCOUNT_ID,
            "userName": username,
        },
        "eventTime": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": event_name,
        "awsRegion": REGION,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.15.0 Python/3.11.0 Linux/6.1.0 botocore/2.0.0",
        "requestParameters": request_params,
        "responseElements": None,
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "readOnly": event_name.startswith(("List", "Get", "Describe")),
        "resources": resources,
        "eventType": "AwsApiCall",
        "managementEvent": False,
        "recipientAccountId": ACCOUNT_ID,
    }


def build_events(
    compromised_user_arn: str,
    app_role_arn: str,
    bucket_name: str,
    base_time: datetime,
) -> list[dict[str, Any]]:
    """
    Build five CloudTrail events representing a realistic attacker kill-chain
    plus one benign baseline.

    Kill-chain sequence (MITRE ATT&CK Cloud):
      T1580  Cloud Infrastructure Discovery  — ListBuckets  (recon)
      T1530  Data from Cloud Storage Object  — GetObject    (exfil)
      T1098  Account Manipulation / Backdoor — PutObject    (persistence)
      T1486  Data Encrypted for Impact       — PutBucketEncryption (extortion)
    Benign:
      Legitimate app-role reads production data — GetObject
    """
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    object_arn = f"arn:aws:s3:::{bucket_name}/config/db_passwords.env"
    backdoor_arn = f"arn:aws:s3:::{bucket_name}/scripts/backup_sync.py"

    events = [
        # ------------------------------------------------------------------
        # Event 1 — Reconnaissance: attacker lists all buckets to map the
        # environment before targeting specific data (T1580).
        # ListBuckets is a *global* S3 call with no bucket parameter, so the
        # attacker gets the full inventory of buckets owned by the account.
        # ------------------------------------------------------------------
        _event(
            event_name="ListBuckets",
            source="s3.amazonaws.com",
            user_type="IAMUser",
            username="compromised-user",
            user_arn=compromised_user_arn,
            source_ip="203.0.113.42",
            resources=[{"ARN": bucket_arn, "accountId": ACCOUNT_ID, "type": "AWS::S3::Bucket"}],
            request_params={},
            timestamp=base_time,
        ),

        # ------------------------------------------------------------------
        # Event 2 — Data Exfiltration: attacker reads a known-sensitive file
        # discovered during recon (T1530).  Targeting a .env file containing
        # production database credentials is a common attacker move after
        # bucket enumeration.  Added a prerequisite ListObjectsV2 that a real
        # attacker would run immediately before GetObject to find file paths;
        # represented here in requestParameters for realism.
        # ------------------------------------------------------------------
        _event(
            event_name="GetObject",
            source="s3.amazonaws.com",
            user_type="IAMUser",
            username="compromised-user",
            user_arn=compromised_user_arn,
            source_ip="203.0.113.42",
            resources=[{"ARN": object_arn, "accountId": ACCOUNT_ID, "type": "AWS::S3::Object"}],
            request_params={
                "bucketName": bucket_name,
                "key": "config/db_passwords.env",
            },
            timestamp=base_time + timedelta(minutes=5),
        ),

        # ------------------------------------------------------------------
        # Event 3 — Persistence: attacker uploads a malicious Python script
        # disguised as a routine backup helper (T1098 / T1505).
        # Naming it "backup_sync.py" blends with legitimate maintenance tasks.
        # A subsequent scheduled job or Lambda trigger would execute it,
        # giving the attacker a persistent foothold.
        # ------------------------------------------------------------------
        _event(
            event_name="PutObject",
            source="s3.amazonaws.com",
            user_type="IAMUser",
            username="compromised-user",
            user_arn=compromised_user_arn,
            source_ip="203.0.113.42",
            resources=[{"ARN": backdoor_arn, "accountId": ACCOUNT_ID, "type": "AWS::S3::Object"}],
            request_params={
                "bucketName": bucket_name,
                "key": "scripts/backup_sync.py",
                "x-amz-server-side-encryption": "AES256",
            },
            timestamp=base_time + timedelta(minutes=20),
        ),

        # ------------------------------------------------------------------
        # Event 4 — Extortion / Ransomware: attacker enables bucket-level
        # encryption with a key they control, locking out the legitimate owner
        # (T1486 — Data Encrypted for Impact).
        # In a real attack this would use a customer-managed KMS key owned by
        # the attacker; the victim cannot decrypt without paying.
        # ------------------------------------------------------------------
        _event(
            event_name="PutBucketEncryption",
            source="s3.amazonaws.com",
            user_type="IAMUser",
            username="compromised-user",
            user_arn=compromised_user_arn,
            source_ip="203.0.113.42",
            resources=[{"ARN": bucket_arn, "accountId": ACCOUNT_ID, "type": "AWS::S3::Bucket"}],
            request_params={
                "bucketName": bucket_name,
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "arn:aws:kms:us-east-1:999999999999:key/attacker-key",
                        }
                    }]
                },
            },
            timestamp=base_time + timedelta(minutes=60),
        ),

        # ------------------------------------------------------------------
        # Event 5 — Benign baseline: legitimate application role reads an
        # object from an internal IP.  Should NOT trigger quarantine.
        # Internal RFC-1918 source IP and app-role principal are both strong
        # benign signals that a detection rule should allow.
        # ------------------------------------------------------------------
        _event(
            event_name="GetObject",
            source="s3.amazonaws.com",
            user_type="AssumedRole",
            username="app-role",
            user_arn=app_role_arn,
            source_ip="10.0.0.1",
            resources=[{"ARN": object_arn, "accountId": ACCOUNT_ID, "type": "AWS::S3::Object"}],
            request_params={
                "bucketName": bucket_name,
                "key": "config/db_passwords.env",
            },
            timestamp=base_time,
        ),
    ]
    return events


# ---------------------------------------------------------------------------
# Store events in S3 in CloudTrail log format
# ---------------------------------------------------------------------------

def upload_events(
    s3: Any,
    bucket_name: str,
    events: list[dict[str, Any]],
    base_time: datetime,
) -> None:
    """
    Write CloudTrail events to S3 using the real CloudTrail path convention:
      AWSLogs/<account>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/<filename>.json.gz
    Each event is uploaded as its own gzip-compressed JSON file so that
    lookups can scan individual records.
    """
    date_prefix = base_time.strftime("%Y/%m/%d")
    s3_prefix = (
        f"AWSLogs/{ACCOUNT_ID}/CloudTrail/{REGION}/{date_prefix}"
    )

    for idx, event in enumerate(events, start=1):
        key = f"{s3_prefix}/cloudtrail-event-{idx:02d}_{uuid.uuid4().hex[:8]}.json.gz"
        payload = json.dumps({"Records": [event]}).encode("utf-8")
        compressed = gzip.compress(payload)
        s3.put_object(Bucket=bucket_name, Key=key, Body=compressed)
        ts = event["eventTime"]
        ip = event["userIdentity"]["userName"]
        print(f"[S3]  Uploaded event {idx}/5 — {event['eventName']} by {ip} at {ts} → s3://{bucket_name}/{key}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Provision LocalStack resources and seed IR scenario data."""
    print("=" * 60)
    print("Sentinel LocalStack Seed")
    print(f"Endpoint : {ENDPOINT}")
    print(f"Region   : {REGION}")
    print("=" * 60)

    iam = make_client("iam")
    s3 = make_client("s3")
    ct = make_client("cloudtrail")

    # --- IAM ---------------------------------------------------------------
    print("\n[1/4] Provisioning IAM resources …")
    compromised_user_arn = create_iam_user(iam, "compromised-user")
    app_role_arn = create_iam_role(iam, "app-role")

    # --- S3 ----------------------------------------------------------------
    print("\n[2/4] Provisioning S3 bucket …")
    bucket_name = "sentinel-logs"
    create_s3_bucket(s3, bucket_name)

    # --- CloudTrail --------------------------------------------------------
    print("\n[3/4] Provisioning CloudTrail trail …")
    create_cloudtrail(ct, "sentinel-trail", bucket_name)

    # --- Seed events -------------------------------------------------------
    print("\n[4/4] Seeding CloudTrail events …")
    base_time = datetime.now(timezone.utc).replace(microsecond=0)
    events = build_events(
        compromised_user_arn=compromised_user_arn,
        app_role_arn=app_role_arn,
        bucket_name=bucket_name,
        base_time=base_time,
    )
    upload_events(s3, bucket_name, events, base_time)

    # --- Summary -----------------------------------------------------------
    print("\n" + "=" * 60)
    print("Seed complete. Event timeline:")
    for idx, ev in enumerate(events, start=1):
        label = "MALICIOUS" if ev["userIdentity"]["userName"] == "compromised-user" else "benign  "
        print(
            f"  {idx}. [{label}] {ev['eventTime']}  {ev['eventName']:<30} "
            f"from {ev['sourceIPAddress']} by {ev['userIdentity']['userName']}"
        )
    print("=" * 60)


if __name__ == "__main__":
    main()
