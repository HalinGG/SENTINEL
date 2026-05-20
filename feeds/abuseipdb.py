"""AbuseIPDB feed integration."""

from typing import Any

import requests
from google.cloud import secretmanager

import config


def _get_api_key() -> str:
    """Fetch AbuseIPDB API key from GCP Secret Manager.

    Returns:
        The API key string.

    Raises:
        google.cloud.exceptions.GoogleCloudError: If Secret Manager access fails.
    """
    client = secretmanager.SecretManagerServiceClient()
    secret_path = client.secret_version_path(
        config.GCP_PROJECT_ID,
        config.ABUSEIPDB_SECRET_NAME,
        "latest",
    )
    response = client.access_secret_version(request={"name": secret_path})
    return response.payload.data.decode("UTF-8")


def query_abuseipdb(ip_address: str) -> dict[str, Any]:
    """Query AbuseIPDB for IP reputation data.

    Args:
        ip_address: The IP address to check.

    Returns:
        JSON response from AbuseIPDB API.

    Raises:
        requests.RequestException: If the HTTP request fails.
        google.cloud.exceptions.GoogleCloudError: If Secret Manager access fails.
    """
    api_key = _get_api_key()

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": config.ABUSEIPDB_MAX_AGE_DAYS,
    }

    response = requests.get(
        config.ABUSEIPDB_URL,
        headers=headers,
        params=params,
        timeout=config.REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    return response.json()
