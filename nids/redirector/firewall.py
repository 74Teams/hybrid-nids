"""Bọc lệnh iptables: một chain NAT riêng chứa rule REDIRECT cho từng IP bị chuyển hướng.

Chỉ nhận IPv4 hợp lệ và luôn gọi iptables với argv dựng sẵn (không qua shell), vì `src_ip` đến từ gói tin của attacker.
"""
import ipaddress
import logging
import subprocess
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("nids.redirector")

CHAIN = "NIDS_REDIRECT"
RUN_TIMEOUT = 5   # giây; iptables treo không được chặn vòng lặp


class FirewallError(Exception):
    """Không chạy được lệnh iptables (thiếu binary, thiếu quyền, quá thời gian hoặc lệnh trả mã lỗi)."""


Runner = Callable[[List[str]], "subprocess.CompletedProcess"]


def default_runner(argv: List[str]) -> "subprocess.CompletedProcess":
    return subprocess.run(argv, capture_output=True, text=True, timeout=RUN_TIMEOUT, shell=False)


def normalize_ip(ip: str) -> str:
    """Trả IPv4 chuẩn hoá hoặc ném `FirewallError`; chuỗi có dấu cách, `;`, xuống dòng hay IPv6 đều bị từ chối."""
    try:
        address = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        raise FirewallError(f"IP không hợp lệ: {ip!r}")
    if address.version != 4:
        raise FirewallError(f"Chỉ hỗ trợ IPv4: {ip!r}")
    return str(address)


class IptablesFirewall:
    def __init__(self, ports: Dict[int, int], runner: Optional[Runner] = None, chain: str = CHAIN):
        self.ports = dict(ports)
        self.chain = chain
        self._runner = runner or default_runner

    def _run(self, args: List[str], check: bool = True) -> int:
        """Chạy `iptables -w -t nat <args>`; trả về mã thoát. `check=False` cho phép mã khác 0 (lệnh kiểm tra `-C`, `-S`)."""
        argv = ["iptables", "-w", "-t", "nat", *args]
        try:
            result = self._runner(argv)
        except (OSError, subprocess.SubprocessError) as e:
            raise FirewallError(f"Không chạy được {' '.join(argv)}: {e}")
        if check and result.returncode != 0:
            raise FirewallError(f"{' '.join(argv)} trả mã {result.returncode}: {(result.stderr or '').strip()}")
        return result.returncode

    def _rule(self, ip: str, src_port: int) -> List[str]:
        return ["-s", ip, "-p", "tcp", "--dport", str(src_port), "-j", "REDIRECT", "--to-ports", str(self.ports[src_port])]

    def check_available(self) -> None:
        """Ném `FirewallError` nếu iptables không dùng được (thiếu binary hoặc quyền NET_ADMIN)."""
        self._run(["-S"])

    def ensure_setup(self) -> None:
        """Tạo chain và jump PREROUTING → chain nếu thiếu; gọi nhiều lần vẫn an toàn."""
        if self._run(["-S", self.chain], check=False) != 0:
            self._run(["-N", self.chain])
        if self._run(["-C", "PREROUTING", "-j", self.chain], check=False) != 0:
            self._run(["-I", "PREROUTING", "1", "-j", self.chain])

    def add(self, ip: str) -> None:
        """Thêm rule chuyển hướng cho `ip` (bỏ qua rule đã có)."""
        ip = normalize_ip(ip)
        for port in self.ports:
            rule = self._rule(ip, port)
            if self._run(["-C", self.chain, *rule], check=False) != 0:
                self._run(["-A", self.chain, *rule])

    def remove(self, ip: str) -> None:
        """Gỡ rule của `ip` (bỏ qua rule không còn)."""
        ip = normalize_ip(ip)
        for port in self.ports:
            rule = self._rule(ip, port)
            if self._run(["-C", self.chain, *rule], check=False) == 0:
                self._run(["-D", self.chain, *rule])

    def flush(self) -> None:
        """Xoá mọi rule trong chain (chain và jump giữ nguyên); chain chưa có thì không làm gì."""
        if self._run(["-S", self.chain], check=False) == 0:
            self._run(["-F", self.chain])
