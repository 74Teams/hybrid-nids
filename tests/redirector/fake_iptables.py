"""iptables giả cho test: hiểu đúng tập lệnh mà `IptablesFirewall` dùng và giữ trạng thái chain/rule trong bộ nhớ."""
import subprocess
from typing import List


class FakeIptables:
    def __init__(self):
        self.calls: List[List[str]] = []
        self.chains = {"PREROUTING": []}   # tên chain -> danh sách rule (tuple argv)
        self.fail_on = None                # hàm (argv) -> True thì ném OSError, mô phỏng lỗi chạy lệnh

    def __call__(self, argv: List[str]):
        self.calls.append(list(argv))
        if self.fail_on and self.fail_on(argv):
            raise OSError("iptables hỏng")
        assert argv[:4] == ["iptables", "-w", "-t", "nat"], argv
        op, *rest = argv[4:]
        ok = subprocess.CompletedProcess(argv, 0, "", "")
        bad = subprocess.CompletedProcess(argv, 1, "", "không có")
        if op == "-S":
            return ok if not rest or rest[0] in self.chains else bad
        if op == "-N":
            if rest[0] in self.chains:
                return bad
            self.chains[rest[0]] = []
            return ok
        if op == "-F":
            self.chains[rest[0]].clear()
            return ok
        chain, rule = rest[0], tuple(rest[1:])
        if op == "-I":
            self.chains[chain].insert(int(rule[0]) - 1, tuple(rule[1:]))
            return ok
        if op == "-C":
            return ok if chain in self.chains and rule in self.chains[chain] else bad
        if op == "-A":
            self.chains[chain].append(rule)
            return ok
        if op == "-D":
            if rule not in self.chains[chain]:
                return bad
            self.chains[chain].remove(rule)
            return ok
        raise AssertionError(f"lệnh không hỗ trợ: {argv}")

    def rules_for(self, ip: str, chain: str = "NIDS_REDIRECT"):
        return [r for r in self.chains.get(chain, []) if r[1] == ip]

    def mutating_calls(self):
        return [c for c in self.calls if c[4] in ("-N", "-A", "-D", "-F", "-I")]
