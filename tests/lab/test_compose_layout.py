"""Kiểm tra docker-compose.yml khớp cấu trúc services/: mỗi service Python build từ Dockerfile của nó, kẻ tấn công nằm trong profile lab."""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVICES = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]

EXPECTED_DOCKERFILES = {
    "nids_sensor": "services/sensor/Dockerfile",
    "honeypot_ssh": "services/honeypot/Dockerfile",
    "nids_redirector": "services/redirector/Dockerfile",
    "nids_api": "services/dashboard/Dockerfile",
}


def test_each_python_service_builds_from_its_own_dockerfile():
    for name, dockerfile in EXPECTED_DOCKERFILES.items():
        build = SERVICES[name]["build"]
        assert build["context"] == "." and build["dockerfile"] == dockerfile, name
        assert (REPO_ROOT / dockerfile).exists(), dockerfile


def test_honeypot_http_reuses_the_honeypot_image():
    assert SERVICES["honeypot_http"]["image"] == SERVICES["honeypot_ssh"]["image"]
    assert "build" not in SERVICES["honeypot_http"]


def test_attacker_only_runs_in_lab_profile():
    assert SERVICES["attacker"]["profiles"] == ["lab"]
    assert all("profiles" not in s for n, s in SERVICES.items() if n != "attacker")


def test_sensor_gets_rules_and_models_read_only():
    volumes = SERVICES["nids_sensor"]["volumes"]
    assert "./data/rules:/app/data/rules:ro" in volumes
    assert "./data/models:/app/data/models:ro" in volumes


def test_dashboard_can_write_rules():
    assert "./data/rules:/app/data/rules" in SERVICES["nids_api"]["volumes"]
