"""Backend configuration, read from environment variables or a local .env file."""

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    # Per-source timeout in seconds (design.md D3).
    source_timeout_seconds: float = 8.0
    internetdb_base_url: str = "https://internetdb.shodan.io"
    rdap_base_url: str = "https://rdap.org"
    abuseipdb_base_url: str = "https://api.abuseipdb.com"
    greynoise_base_url: str = "https://api.greynoise.io"
    virustotal_base_url: str = "https://www.virustotal.com"
    ipinfo_base_url: str = "https://api.ipinfo.io"

    # API keys (design.md section 4, "Key handling"). SecretStr keeps a key out of repr(), logs
    # and tracebacks; it is unwrapped only where the request header is built. An empty value
    # means "no key", and that source reports `not_configured`.
    abuseipdb_api_key: SecretStr = SecretStr("")
    greynoise_api_key: SecretStr = SecretStr("")
    virustotal_api_key: SecretStr = SecretStr("")
    ipinfo_token: SecretStr = SecretStr("")


@lru_cache
def get_settings() -> Settings:
    return Settings()
