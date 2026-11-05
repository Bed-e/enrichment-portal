"""Frontend configuration. The frontend reads only the backend's URL, never a key."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    backend_url: str = "http://127.0.0.1:8000"
    # Longer than the backend's per-source timeout, so the backend answers first.
    backend_timeout_seconds: float = 20.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
