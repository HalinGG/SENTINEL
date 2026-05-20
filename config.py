"""Configuration for Sentinel."""

# GCP project identifier
GCP_PROJECT_ID: str = "ai-sentinel-496600"

# Secret name for AbuseIPDB API key in Secret Manager
ABUSEIPDB_SECRET_NAME: str = "abuseipdb-key"

# Secret name for AlienVault OTX API key in Secret Manager
ALIEN_SECRET_NAME: str = "alien-key"

# AbuseIPDB API endpoint
ABUSEIPDB_URL: str = "https://api.abuseipdb.com/api/v2/check"

# AlienVault OTX base URL for indicators
ALIEN_OTX_BASE_URL: str = "https://otx.alienvault.com/api/v1/indicators"

# HTTP request timeout in seconds
REQUEST_TIMEOUT: int = 15

# Maximum age of AbuseIPDB reports in days
ABUSEIPDB_MAX_AGE_DAYS: int = 90
