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
    ssh_bruteforce_threshold: int = 5       # số lần đăng nhập để coi là brute force
    ssh_bruteforce_window: int = 60         # giây tối đa giữa hai lần đăng nhập của cùng một đợt

    # Giới hạn tài nguyên SSH (0 = tắt giới hạn đó)
    ssh_max_connections: int = 100          # tổng kết nối đồng thời
    ssh_max_connections_per_ip: int = 20    # hydra -t 4 và redirector nằm xa dưới mức này
    ssh_handshake_timeout: float = 30       # giây cho bước bắt tay SSH (kex)
    ssh_auth_timeout: float = 90            # giây cho tới khi client mở channel (gồm cả gõ mật khẩu tay)
    ssh_idle_timeout: float = 120           # giây không gõ gì trong shell thì đóng
    ssh_session_max_seconds: float = 600    # tổng thời gian tối đa của một phiên shell
    ssh_max_command_bytes: int = 4096       # dòng lệnh chưa Enter dài hơn thì đóng phiên

    # HTTP
    http_port: int = 8080
    http_threads: int = 8                   # số worker của waitress
    http_max_connections: int = 100         # waitress ngừng accept khi chạm trần
    http_request_timeout: float = 30        # giây kết nối không hoạt động thì bị dọn (channel_timeout)
    http_max_body_bytes: int = 16 * 1024    # body lớn hơn bị từ chối 413
    http_username: str = "admin"
    http_password: str = "password"

    @model_validator(mode="after")
    def _fill_paths(self):
        self.data_dir = self.data_dir.resolve()
        if self.host_key_path is None:
            self.host_key_path = self.data_dir / "server.key"
        return self


settings = Settings()
