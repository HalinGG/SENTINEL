"""AlienVault OTX feed integration."""

import re
from typing import Any

import requests
from google.cloud import secretmanager

import config


def _get_api_key() -> str:
    """Fetch AlienVault OTX API key from GCP Secret Manager.

    Returns:
        The API key string.

    Raises:
        google.cloud.exceptions.GoogleCloudError: If Secret Manager access fails.
    """
    client = secretmanager.SecretManagerServiceClient()
    secret_path = client.secret_version_path(
        config.GCP_PROJECT_ID,
        config.ALIEN_SECRET_NAME,
        "latest",
    )
    response = client.access_secret_version(request={"name": secret_path})
    return response.payload.data.decode("UTF-8")


def _detect_indicator_type(indicator: str) -> str:
    """Detect the type of indicator (IPv4, domain, or file hash).

    Args:
        indicator: The indicator string to classify.

    Returns:
        One of "IPv4", "domain", or "file".
    """
    # Check for IPv4 address
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ipv4_pattern, indicator):
        return "IPv4"

    # Check for file hash (MD5: 32, SHA-1: 40, SHA-256: 64 hex chars)
    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
    if re.match(hash_pattern, indicator):
        return "file"

    # Default to domain
    return "domain"


def query_alienvault(indicator: str) -> dict[str, Any]:
    """Query AlienVault OTX for indicator reputation data.

    Args:
        indicator: The indicator to check (IP, domain, or hash).

    Returns:
        JSON response from AlienVault OTX API.

    Raises:
        requests.RequestException: If the HTTP request fails.
        google.cloud.exceptions.GoogleCloudError: If Secret Manager access fails.
    """
    api_key = _get_api_key()
    indicator_type = _detect_indicator_type(indicator)

    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json",
    }

    url = f"{config.ALIEN_OTX_BASE_URL}/{indicator_type}/{indicator}/general"

    response = requests.get(
        url,
        headers=headers,
        timeout=config.REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    return response.json()
