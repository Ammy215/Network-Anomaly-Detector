from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """App configuration, loaded from backend/.env.

    Every field is optional in Phase 0 — nothing calls Supabase or any
    external API yet, so a missing key must never crash startup. Fields
    become required as the phase that actually uses them arrives.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    backend_cors_origins: str = "http://localhost:5173"

    supabase_url: Optional[str] = None
    supabase_anon_key: Optional[str] = None
    supabase_service_role_key: Optional[str] = None

    abuseipdb_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    ipinfo_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    nvd_api_key: Optional[str] = None

    llm_api_key: Optional[str] = None
    vector_db_url: Optional[str] = None

    # Phase 1 — PCAP upload & flow assembly
    flow_inactivity_timeout_seconds: int = 120
    max_upload_size_bytes: int = 50 * 1024 * 1024
    # Explicit override if tshark isn't discoverable on PATH (common right
    # after a fresh Wireshark install, until the shell/session restarts).
    tshark_path: Optional[str] = None

    # Phase 11 -- optional outbound integrations with the author's other
    # projects. Both empty/disabled by default; each fires independently
    # and neither requires or affects the other. See docs/INTEGRATIONS.md.
    mini_siem_webhook_url: Optional[str] = None
    threathunter_endpoint_url: Optional[str] = None

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",")]


settings = Settings()
