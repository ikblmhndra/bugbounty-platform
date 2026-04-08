"""
Application configuration using Pydantic Settings.
All values are loaded from environment variables or .env file.
"""
from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    app_env: str = "development"
    app_secret_key: str = "changeme"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = False

    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "bugbounty"
    postgres_user: str = "bugbounty"
    postgres_password: str = "changeme"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_database_url(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # Celery
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"

    # Telegram
    telegram_bot_token: str = ""
    telegram_allowed_users: str = ""

    @property
    def allowed_telegram_users(self) -> list[int]:
        if not self.telegram_allowed_users:
            return []
        return [int(u.strip()) for u in self.telegram_allowed_users.split(",") if u.strip()]

    # Tool paths
    subfinder_path: str = "subfinder"
    assetfinder_path: str = "assetfinder"
    httpx_path: str = "httpx"
    gau_path: str = "gau"
    waybackurls_path: str = "waybackurls"
    katana_path: str = "katana"
    ffuf_path: str = "ffuf"
    nuclei_path: str = "nuclei"
    gowitness_path: str = "gowitness"

    # Scan configuration
    default_scan_timeout: int = 3600
    max_parallel_tasks: int = 5
    nuclei_severity: str = "low,medium,high,critical"
    ffuf_wordlist: str = "/opt/wordlists/ffuf/common.txt"

    # Output directories
    reports_dir: str = "./reports"
    screenshots_dir: str = "./screenshots"

    # Frontend
    next_public_api_url: str = "http://localhost:8000"

    # Sentry (optional)
    sentry_dsn: Optional[str] = None


@lru_cache()
def get_settings() -> Settings:
    return Settings()
