"""Settings, read from PHISHGUARD_* environment variables with safe defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _env(name: str, default: str) -> str:
    return os.environ.get(f"PHISHGUARD_{name}", default)


@dataclass(frozen=True)
class Settings:
    db_path: Path = BACKEND_DIR / "data" / "phishguard.db"
    model_dir: Path = BACKEND_DIR / "models"
    # Admin endpoints are open when no token is set: fine on localhost, and
    # the startup log warns about it. Set PHISHGUARD_ADMIN_TOKEN anywhere else.
    admin_token: str | None = None
    cors_origins: tuple[str, ...] = field(default=("http://localhost:3100", "http://127.0.0.1:3100"))
    rate_capacity: float = 30          # burst size
    rate_refill_per_sec: float = 0.5   # sustained: 30 tokens per minute
    full_scan_cost: float = 5          # full scans make outbound network calls
    scan_cache_ttl: float = 600        # 10 minutes
    host_cache_ttl: float = 6 * 3600   # 6 hours

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            db_path=Path(_env("DB_PATH", str(cls.db_path))),
            model_dir=Path(_env("MODEL_DIR", str(cls.model_dir))),
            admin_token=_env("ADMIN_TOKEN", "") or None,
            cors_origins=tuple(o.strip() for o in _env(
                "CORS_ORIGINS", "http://localhost:3100,http://127.0.0.1:3100").split(",") if o.strip()),
            rate_capacity=float(_env("RATE_CAPACITY", "30")),
            rate_refill_per_sec=float(_env("RATE_REFILL", "0.5")),
            full_scan_cost=float(_env("FULL_SCAN_COST", "5")),
            scan_cache_ttl=float(_env("SCAN_CACHE_TTL", "600")),
            host_cache_ttl=float(_env("HOST_CACHE_TTL", str(6 * 3600))),
        )
