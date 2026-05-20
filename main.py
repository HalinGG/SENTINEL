"""Sentinel entry point."""

from typing import Any

from feeds import abuseipdb, alien


def query_threat_intel(indicator: str) -> dict[str, Any]:
    """Query multiple threat intelligence feeds for indicator data.

    Calls AbuseIPDB and AlienVault OTX feeds, capturing errors per feed
    to allow partial results if one feed fails.

    Args:
        indicator: The indicator to check (IP, domain, or hash).

    Returns:
        Dictionary with keys:
        - "abuseipdb": Result dict or error dict with "error" key
        - "alienvault": Result dict or error dict with "error" key
    """
    results: dict[str, Any] = {}

    # Query AbuseIPDB
    try:
        results["abuseipdb"] = abuseipdb.query_abuseipdb(indicator)
    except Exception as e:
        results["abuseipdb"] = {"error": str(e)}

    # Query AlienVault
    try:
        results["alienvault"] = alien.query_alienvault(indicator)
    except Exception as e:
        results["alienvault"] = {"error": str(e)}

    return results
