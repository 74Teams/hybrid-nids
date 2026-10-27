"""Kiểm tra lab/attacker/Dockerfile dùng Kali và docker-compose.yml build đúng dockerfile này."""

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_PATH = REPO_ROOT / "lab" / "attacker" / "Dockerfile"
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"

REQUIRED_PACKAGES = [
    "nmap",
    "hping3",
    "hydra",
    "ftp",
    "netcat-openbsd",
    "iputils-ping",
    "dnsutils",
    "snmp",
    "sqlmap",
    "nikto",
    "masscan",
    "python3-scapy",
    "openssh-client",
]


def test_dockerfile_exists_and_uses_kali():
    assert DOCKERFILE_PATH.exists(), "lab/attacker/Dockerfile phải tồn tại"
    lines = DOCKERFILE_PATH.read_text(encoding="utf-8").splitlines()
    from_lines = [line for line in lines if line.strip().upper().startswith("FROM")]
    assert from_lines, "Dockerfile phải có dòng FROM"
    assert "kalilinux/kali-rolling" in from_lines[0]


def test_dockerfile_installs_required_tools():
    text = DOCKERFILE_PATH.read_text(encoding="utf-8")
    for pkg in REQUIRED_PACKAGES:
        assert re.search(rf"\b{pkg}\b", text), f"Thiếu gói {pkg} trong Dockerfile"


def test_compose_attacker_builds_from_local_dockerfile():
    with COMPOSE_PATH.open(encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    attacker = compose["services"]["attacker"]
    build = attacker.get("build")
    assert build is not None, "service attacker phải có build"
    if isinstance(build, str):
        assert build == "./lab/attacker"
    else:
        assert build.get("context") == "./lab/attacker"

    assert attacker.get("image") != "python:3.10-slim"
