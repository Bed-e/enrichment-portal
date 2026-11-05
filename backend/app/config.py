"""Backend configuration, read from environment variables or a local .env file."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    # Per-source timeout in seconds (design.md D3).
    source_timeout_seconds: float = 8.0
    internetdb_base_url: str = "https://internetdb.shodan.io"
    rdap_base_url: str = "https://rdap.org"


@lru_cache
def get_settings() -> Settings:
    return Settings()
