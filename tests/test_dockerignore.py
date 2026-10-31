"""Kiểm tra .dockerignore loại các file bí mật khỏi image (Dockerfile dùng COPY . .)."""

from pathlib import Path

DOCKERIGNORE_PATH = Path(__file__).resolve().parents[1] / ".dockerignore"

MUST_IGNORE = [".git", ".env", "config/settings.yaml", "data", "*.db"]


def test_dockerignore_excludes_secrets():
    lines = {l.strip() for l in DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines()}
    missing = [p for p in MUST_IGNORE if p not in lines]
    assert not missing, f".dockerignore thiếu: {missing}"
