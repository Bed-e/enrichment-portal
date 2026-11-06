"""Response bodies built from the providers' DOCUMENTED shapes, not recorded.

Real recordings cover what a provider returned for a lookup. These cover what we cannot or
should not provoke on purpose: a quota error (it would burn the free quota), a rejected key
(it needs a bad key), or a response the provider has not returned to us yet. Every body here is
therefore labelled synthetic, and none comes from a real account. All of them use fake values.
"""

FAKE_KEYS = {
    "abuseipdb": "FAKE-ABUSEIPDB-KEY-0000",
    "greynoise": "FAKE-GREYNOISE-KEY-0000",
    "virustotal": "FAKE-VIRUSTOTAL-KEY-0000",
    "ipinfo": "FAKE-IPINFO-TOKEN-0000",
}

# AbuseIPDB: a 429 carries an `errors` list (docs.abuseipdb.com, "Check" endpoint).
ABUSEIPDB_QUOTA = {
    "errors": [
        {
            "detail": "Daily rate limit of 1000 requests exceeded for this endpoint.",
            "status": 429,
        }
    ]
}
# AbuseIPDB: an IP with reports, for the `ok` path (recorded 8.8.8.8 is whitelisted).
ABUSEIPDB_REPORTED = {
    "data": {
        "ipAddress": "203.0.114.7",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 100,
        "countryCode": "ZZ",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting",
        "domain": "example.net",
        "hostnames": [],
        "isTor": False,
        "totalReports": 12,
        "numDistinctUsers": 7,
        "lastReportedAt": "2026-11-05T10:00:00+00:00",
    }
}

# GreyNoise Community: shape of a 200 for a noise IP (docs.greynoise.io, Community API). No real
# "ok" response was available: 8.8.8.8 and 1.1.1.1 both answered 404 on the free tier.
GREYNOISE_OK = {
    "ip": "203.0.114.7",
    "noise": True,
    "riot": False,
    "classification": "malicious",
    "name": "unknown",
    "link": "https://viz.greynoise.io/ip/203.0.114.7",
    "last_seen": "2026-11-04",
    "message": "Success",
}
GREYNOISE_QUOTA = {"message": "Rate limit exceeded. Weekly lookup limit reached."}

# VirusTotal: error bodies are {"error": {"code", "message"}} (docs.virustotal.com, "Errors").
VIRUSTOTAL_NOT_FOUND = {
    "error": {"code": "NotFoundError", "message": "IP address 203.0.114.7 not found"}
}
VIRUSTOTAL_QUOTA = {
    "error": {"code": "QuotaExceededError", "message": "Quota exceeded for this API key"}
}
VIRUSTOTAL_BAD_KEY = {"error": {"code": "WrongCredentialsError", "message": "Wrong API key"}}

# ipinfo Lite: error body shape is not documented, so only the status codes are relied on.
IPINFO_NOT_FOUND = {
    "status": 404,
    "error": {"title": "Wrong ip", "message": "Please provide a valid IP address"},
}
