"""Kiểm tra lab/victim/Dockerfile và lab/victim/start.sh chạy nhiều dịch vụ, docker-compose.yml build đúng image này."""

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_PATH = REPO_ROOT / "lab" / "victim" / "Dockerfile"
START_SCRIPT_PATH = REPO_ROOT / "lab" / "victim" / "start.sh"
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"

REQUIRED_PACKAGES = ["nginx", "vsftpd", "openssh-server", "ncat"]


def test_dockerfile_exists_and_installs_services():
    assert DOCKERFILE_PATH.exists(), "lab/victim/Dockerfile phải tồn tại"
    text = DOCKERFILE_PATH.read_text(encoding="utf-8")
    for pkg in REQUIRED_PACKAGES:
        assert re.search(rf"\b{pkg}\b", text), f"Thiếu gói {pkg} trong Dockerfile"


def test_start_script_runs_nginx_in_foreground():
    assert START_SCRIPT_PATH.exists(), "lab/victim/start.sh phải tồn tại"
    text = START_SCRIPT_PATH.read_text(encoding="utf-8")
    assert "nginx" in text
    assert "daemon off" in text

    non_empty_lines = [line for line in text.splitlines() if line.strip()]
    assert non_empty_lines, "start.sh không được rỗng"
    last_line = non_empty_lines[-1]
    assert "nginx" in last_line and "daemon off" in last_line, (
        "Dòng chạy nginx phải là dòng cuối cùng không rỗng của start.sh"
    )


def test_start_script_enables_ftp_anonymous():
    texts = [START_SCRIPT_PATH.read_text(encoding="utf-8")]
    if DOCKERFILE_PATH.exists():
        texts.append(DOCKERFILE_PATH.read_text(encoding="utf-8"))
    assert any("anonymous_enable=YES" in t for t in texts), (
        "Phải có anonymous_enable=YES trong start.sh hoặc file cấu hình copy vào image"
    )


def test_dockerfile_ftp_anonymous_verified_by_content_not_sed_exitcode():
    """sed trả exit code 0 ngay cả khi pattern không khớp dòng nào, nên nhánh
    fallback (echo append) phải được quyết định bằng cách grep lại nội dung
    file sau khi sed chạy, không phải dựa vào exit code của sed."""
    text = DOCKERFILE_PATH.read_text(encoding="utf-8")
    match = re.search(r"RUN[^\n]*anonymous_enable[\s\S]*?(?=\n\n|\nCOPY|\Z)", text)
    assert match, "Không tìm thấy RUN xử lý anonymous_enable trong Dockerfile"
    block = match.group(0)

    assert "grep -q" in block, (
        "Phải grep -q xác nhận nội dung file sau sed, không dựa vào exit code của sed"
    )
    grep_idx = block.index("grep -q")
    echo_idx = block.rindex("echo")
    assert grep_idx < echo_idx, (
        "grep -q phải chạy trước nhánh echo fallback để quyết định có cần append hay không"
    )


def test_compose_victim_builds_from_local_dockerfile():
    with COMPOSE_PATH.open(encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    victim = compose["services"]["victim_app"]
    build = victim.get("build")
    assert build is not None, "service victim_app phải có build"
    if isinstance(build, str):
        assert build == "./lab/victim"
    else:
        assert build.get("context") == "./lab/victim"

    assert victim.get("image") != "nginx:alpine"

    ip = victim["networks"]["nids_isolated_net"]["ipv4_address"]
    assert ip == "172.28.0.50"
