"""MCP tools for security operations: CloudTrail query, IAM policy inspection, principal quarantine."""

import gzip
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def _get_s3_client():
    """Create S3 client connected to LocalStack."""
    return boto3.client(
        "s3",
        endpoint_url="http://localhost:4566",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-west-1",
    )


def _get_iam_client():
    """Create IAM client connected to LocalStack."""
    return boto3.client(
        "iam",
        endpoint_url="http://localhost:4566",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-west-1",
    )


def query_cloudtrail(principal_id: str) -> Dict[str, Any]:
    """
    Query CloudTrail events for a specific principal.

    Reads all .json.gz CloudTrail event files from S3 bucket "sentinel-logs",
    decompresses them, parses JSON, and filters events where userIdentity.userName
    matches the provided principal_id.

    Args:
        principal_id: The AWS principal/user name to query (e.g., "compromised-user")

    Returns:
        Dict with keys:
        - principal_id: The queried principal ID
        - event_count: Number of events found
        - events: List of CloudTrail events with eventTime, eventName, sourceIPAddress
    """
    logger.info(f"Querying CloudTrail events for principal: {principal_id}")

    s3 = _get_s3_client()
    events = []

    try:
        # List all objects in the CloudTrail path
        prefix = "AWSLogs/000000000000/CloudTrail/us-west-1/2026/05/22/"
        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket="sentinel-logs", Prefix=prefix)

        for page in pages:
            if "Contents" not in page:
                continue

            for obj in page["Contents"]:
                key = obj["Key"]
                if not key.endswith(".json.gz"):
                    continue

                logger.debug(f"Processing CloudTrail file: {key}")

                try:
                    # Download and decompress the gzip file
                    response = s3.get_object(Bucket="sentinel-logs", Key=key)
                    with gzip.GzipFile(fileobj=response["Body"]) as gzipfile:
                        content = gzipfile.read()
                        data = json.loads(content)

                    # CloudTrail events are wrapped in Records array
                    records = data.get("Records", [])
                    for event in records:
                        # Filter by principal_id
                        user_identity = event.get("userIdentity", {})
                        if user_identity.get("userName") == principal_id:
                            # Extract required fields
                            filtered_event = {
                                "eventTime": event.get("eventTime"),
                                "eventName": event.get("eventName"),
                                "sourceIPAddress": event.get("sourceIPAddress"),
                            }
                            events.append(filtered_event)
                            logger.debug(
                                f"Found event for {principal_id}: {event.get('eventName')}"
                            )

                except Exception as e:
                    logger.warning(f"Error processing {key}: {e}")
                    continue

    except ClientError as e:
        logger.error(f"S3 error querying CloudTrail: {e}")
    except Exception as e:
        logger.error(f"Unexpected error querying CloudTrail: {e}")

    result = {
        "principal_id": principal_id,
        "event_count": len(events),
        "events": events,
    }
    logger.info(f"CloudTrail query complete: found {len(events)} events for {principal_id}")
    return result


def get_iam_policy(principal_id: str) -> Dict[str, Any]:
    """
    Get IAM policies attached to a user.

    Queries IAM for all policies attached to the specified user using
    list_attached_user_policies.

    Args:
        principal_id: The IAM user name

    Returns:
        Dict with keys:
        - principal_id: The queried principal ID
        - attached_policies: List of dicts with PolicyName and Arn
    """
    logger.info(f"Fetching IAM policies for principal: {principal_id}")

    iam = _get_iam_client()
    policies = []

    try:
        response = iam.list_attached_user_policies(UserName=principal_id)
        policies = response.get("AttachedPolicies", [])
        logger.info(f"Found {len(policies)} attached policies for {principal_id}")

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info(f"User {principal_id} does not exist")
        else:
            logger.error(f"IAM error fetching policies for {principal_id}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error fetching IAM policies: {e}")

    result = {
        "principal_id": principal_id,
        "attached_policies": policies,
    }
    return result


def quarantine_principal(principal_id: str) -> Dict[str, Any]:
    """
    Quarantine a principal by disabling access and attaching deny-all policy.

    Deletes all access keys for the user and attaches an inline deny-all policy.
    Safe to call multiple times (idempotent).

    Args:
        principal_id: The IAM user name to quarantine

    Returns:
        Dict with keys:
        - principal_id: The quarantined principal ID
        - actions_taken: List of action strings (e.g., "deleted_access_key_XXXXX", "deny_all_policy_attached")
        - timestamp: ISO8601 timestamp of when quarantine was performed
    """
    logger.info(f"Quarantining principal: {principal_id}")

    iam = _get_iam_client()
    actions_taken = []
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        # Delete all access keys
        try:
            response = iam.list_access_keys(UserName=principal_id)
            access_keys = response.get("AccessKeyMetadata", [])

            for key in access_keys:
                access_key_id = key["AccessKeyId"]
                try:
                    iam.delete_access_key(
                        UserName=principal_id, AccessKeyId=access_key_id
                    )
                    action = f"deleted_access_key_{access_key_id}"
                    actions_taken.append(action)
                    logger.info(f"Deleted access key {access_key_id} for {principal_id}")
                except ClientError as e:
                    logger.warning(f"Error deleting access key {access_key_id}: {e}")

        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                logger.warning(f"Error listing access keys for {principal_id}: {e}")

        # Attach deny-all inline policy
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }

        try:
            iam.put_user_policy(
                UserName=principal_id,
                PolicyName="DenyAllPolicy",
                PolicyDocument=json.dumps(deny_policy),
            )
            actions_taken.append("deny_all_policy_attached")
            logger.info(f"Attached deny-all policy to {principal_id}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                logger.info(f"User {principal_id} does not exist, skipping policy attachment")
            else:
                logger.error(f"Error attaching deny-all policy: {e}")

    except Exception as e:
        logger.error(f"Unexpected error quarantining principal: {e}")

    result = {
        "principal_id": principal_id,
        "actions_taken": actions_taken,
        "timestamp": timestamp,
    }
    logger.info(f"Quarantine complete for {principal_id}. Actions: {actions_taken}")
    return result
