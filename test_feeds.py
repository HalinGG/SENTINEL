"""Tests for the feeds package."""

import json

from main import query_threat_intel


def main() -> None:
    """Query threat intelligence feeds and display results."""
    indicator = "8.8.8.8"
    print(f"Querying threat intelligence feeds for: {indicator}\n")

    results = query_threat_intel(indicator)

    # Print formatted results
    print(json.dumps(results, indent=2))

    # Show feed status
    print("\nFeed Status:")
    for feed_name, feed_result in results.items():
        if "error" in feed_result:
            print(f"  {feed_name}: ❌ FAILED - {feed_result['error']}")
        else:
            print(f"  {feed_name}: ✓ SUCCESS")


if __name__ == "__main__":
    main()
