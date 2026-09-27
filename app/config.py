from typing import Literal

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CTI Triage"
    app_env: str = "development"
    database_path: Path = Path("data/cti.db")
    csv_export_path: Path = Path("data/triage_history.csv")
    virustotal_api_key: str | None = None
    malwarebazaar_auth_key: str | None = None
    openai_api_key: str | None = None
    openai_model: str = "gpt-5-mini"
    request_timeout_seconds: float = 30.0
    max_relationship_items: int = 20
    enable_genai: bool = True

    genai_provider: Literal[
        "openai",
        "anthropic",
    ] = "openai"

    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-6"
    anthropic_max_tokens: int = 4096


    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()