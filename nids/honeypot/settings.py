"""
Cấu hình honeypot. Thứ tự ưu tiên: biến môi trường HONEYPY_* > giá trị mặc định dưới đây.
Host key SSH nằm trong data/ (gitignore), tự sinh ở lần chạy đầu.
"""
from pathlib import Path
from typing import Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HONEYPY_", extra="ignore")

    data_dir: Path = BASE_DIR / "data"
    host_key_path: Optional[Path] = None    # mặc định: data/server.key

    bind_address: str = "0.0.0.0"

    # SSH
    ssh_port: int = 2222
    ssh_banner: str = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
    ssh_prompt: str = "corporate-jumpbox2$ "
    ssh_motd: str = "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)"

    # HTTP
    http_port: int = 8080
    http_username: str = "admin"
    http_password: str = "password"

    @model_validator(mode="after")
    def _fill_paths(self):
        self.data_dir = self.data_dir.resolve()
        if self.host_key_path is None:
            self.host_key_path = self.data_dir / "server.key"
        return self


settings = Settings()
