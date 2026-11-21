"""Chuyển bộ rule Snort 2.9 (Snort Community Ruleset) sang tập con cú pháp Snort 3 mà engine hiểu.

Chạy từ thư mục gốc repo: python -m tools.rules.snort2_convert
Đọc data/rules/upstream/community.rules, ghi data/rules/community-*.rules (bật mặc định, tắt từng file trên trang Rules).
Chỉ giữ rule mà sau khi chuyển vẫn đúng nghĩa và parse sạch bằng RuleManager; rule dùng option engine chưa hỗ trợ bị loại.
"""
import argparse
import logging
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from nids.engine.rule_manager import COMMENTED_RULE, RuleManager
from nids.logger import setup_logging

logger = logging.getLogger("nids.tools")

DEFAULT_SOURCE = "data/rules/upstream/community.rules"
DEFAULT_OUT = "data/rules"

# SID của rule tự viết nằm từ 1000000 trở lên, rule community phải nằm dưới dải này để không trùng
CUSTOM_SID_MIN = 1000000

# Rule community báo nhầm trên traffic bình thường (đo bằng data/pcap/benign_0900.pcap). Mỗi SID kèm lý do.
DENY_SIDS: Dict[int, str] = {
    1917: "SSDP M-SEARCH (UPnP discover) là traffic LAN bình thường",
}

PROTOCOLS = {"tcp", "udp", "icmp", "ip"}

# Priority theo classification.config của Snort (1 cao nhất); engine chỉ có thang 1-3 nên mức 4 gộp vào 3
CLASSTYPE_PRIORITY = {
    "attempted-admin": 1, "attempted-user": 1, "inappropriate-content": 1, "policy-violation": 1,
    "shellcode-detect": 1, "successful-admin": 1, "successful-user": 1, "trojan-activity": 1,
    "unsuccessful-user": 1, "web-application-attack": 1, "client-side-exploit": 1, "exploit-kit": 1,
    "attempted-dos": 2, "attempted-recon": 2, "bad-unknown": 2, "default-login-attempt": 2,
    "denial-of-service": 2, "misc-attack": 2, "non-standard-protocol": 2, "rpc-portmap-decode": 2,
    "successful-dos": 2, "successful-recon-largescale": 2, "successful-recon-limited": 2,
    "suspicious-filename-detect": 2, "suspicious-login": 2, "system-call-detect": 2,
    "unusual-client-port-connection": 2, "web-application-activity": 2,
    "icmp-event": 3, "misc-activity": 3, "network-scan": 3, "not-suspicious": 3,
    "protocol-command-decode": 3, "string-detect": 3, "unknown": 3, "tcp-connection": 3,
}
DEFAULT_PRIORITY = 3

# Option Snort 2 gắn vào content ngay trước nó
CONTENT_FLAGS = {"nocase"}
CONTENT_NUMBERS = {"depth", "offset", "distance", "within"}

# Buffer modifier Snort 2 đứng sau content -> (sticky buffer Snort 3, tên header nếu có).
# Buffer http_uri của engine chưa URL-decode nên http_raw_uri khớp cùng nghĩa.
BUFFER_MODIFIERS: Dict[str, Tuple[str, Optional[str]]] = {
    "http_uri": ("http_uri", None),
    "http_raw_uri": ("http_uri", None),
    "http_header": ("http_header", None),
    "http_raw_header": ("http_header", None),
    "http_client_body": ("http_client_body", None),
    "http_method": ("http_method", None),
    "http_cookie": ("http_header", "cookie"),
    "http_raw_cookie": ("http_header", "cookie"),
}

# Cờ pcre của Snort 2 chọn buffer
PCRE_BUFFER_FLAGS: Dict[str, Tuple[str, Optional[str]]] = {
    "U": ("http_uri", None), "I": ("http_uri", None),
    "H": ("http_header", None), "D": ("http_header", None),
    "P": ("http_client_body", None), "M": ("http_method", None),
    "C": ("http_header", "cookie"), "K": ("http_header", "cookie"),
}
PCRE_KEEP_FLAGS = "ismx"

# Option giữ nguyên giá trị khi chuyển
PASSTHROUGH = {"flags", "dsize", "itype", "icode", "detection_filter"}
IGNORED_FLOW_TOKENS = {"no_stream", "only_stream"}

PKT_DATA: Tuple[str, Optional[str]] = ("pkt_data", None)
Buffer = Tuple[str, Optional[str]]

# Tên file -> tiền tố msg; rule không khớp nhóm nào rơi vào community-protocol
WEB_PREFIXES = ("SERVER-WEBAPP", "SERVER-IIS", "SERVER-APACHE", "BROWSER", "EXPLOIT-KIT")
MALWARE_FAMILIES = {"MALWARE", "INDICATOR", "PUA"}
SERVER_FAMILIES = {"SERVER", "SQL", "OS"}
OUTPUT_FILES = ("community-web", "community-malware", "community-server", "community-protocol")

FILE_HEADER = """\
# {name}.rules: SINH TỰ ĐỘNG, KHÔNG sửa tay (sửa sẽ bị ghi đè khi chạy lại bộ chuyển đổi).
# Nguồn: data/rules/upstream/community.rules (Snort Community Ruleset, GPLv2, bản quyền Sourcefire/Cisco và các tác giả).
# Đã chuyển sang cú pháp Snort 3 của engine, rule dùng option chưa hỗ trợ đã bị loại.
# Sinh lại: python -m tools.rules.snort2_convert
"""


class Skip(Exception):
    """Rule không chuyển được; lý do dùng để thống kê."""


@dataclass
class Item:
    kind: str                       # "content" hoặc "pcre"
    value: str
    buffer: Buffer = PKT_DATA
    nocase: bool = False
    fast_pattern: bool = False
    numbers: Optional[Dict[str, int]] = None
    buffer_set: bool = False


def _sticky(buffer: Buffer) -> str:
    name, header_field = buffer
    return f"{name}:field {header_field}" if header_field else name


def _number(name: str, value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise Skip(f"{name} dùng biến hoặc giá trị lạ")
    if number < 0:
        raise Skip(f"{name} âm")
    return number


def _convert_pcre(value: str) -> Tuple[str, Buffer]:
    """pcre:"/regex/flags" kiểu Snort 2: bỏ cờ chọn buffer, đưa buffer đó thành sticky buffer."""
    value = value.strip()
    if not (value.startswith('"') and value.endswith('"')):
        raise Skip("pcre phủ định hoặc không có ngoặc kép")
    inner = value[1:-1]
    last_slash = inner.rfind("/")
    if not inner.startswith("/") or last_slash == 0:
        raise Skip("pcre sai dạng")
    kept, buffers = "", []
    for flag in inner[last_slash + 1:]:
        if flag in PCRE_KEEP_FLAGS:
            kept += flag
        elif flag in PCRE_BUFFER_FLAGS:
            buffers.append(PCRE_BUFFER_FLAGS[flag])
        else:
            raise Skip(f"cờ pcre {flag} không hỗ trợ")
    if len(set(buffers)) > 1:
        raise Skip("pcre chọn nhiều buffer")
    return f'"{inner[:last_slash + 1]}{kept}"', (buffers[0] if buffers else PKT_DATA)


def _content_text(item: Item) -> str:
    text = f"content:{item.value}"
    if item.nocase:
        text += ",nocase"
    for key in ("offset", "depth", "distance", "within"):
        if item.numbers and key in item.numbers:
            text += f",{key} {item.numbers[key]}"
    if item.fast_pattern:
        text += ",fast_pattern"
    return text


def _last_content(items: List[Item], option: str) -> Item:
    if not items or items[-1].kind != "content":
        raise Skip(f"{option} không đứng sau content")
    return items[-1]


def convert_line(line: str, manager: RuleManager) -> Tuple[int, str, str]:
    """Chuyển một dòng rule Snort 2. Trả về (sid, msg, rule Snort 3); ném Skip nếu phải loại."""
    if "(" not in line or not line.endswith(")"):
        raise Skip("không phải rule")
    header, options_text = line.split("(", 1)
    header_tokens = header.split()
    if len(header_tokens) != 7:
        raise Skip("header sai")
    if header_tokens[0].lower() != "alert":
        raise Skip("action khác alert")
    if header_tokens[1].lower() not in PROTOCOLS:
        raise Skip(f"giao thức {header_tokens[1].lower()} chưa hỗ trợ")

    items: List[Item] = []
    kept: Dict[str, List[str]] = {key: [] for key in ("msg", "flow", "reference", "classtype", "priority")}
    passthrough: List[str] = []
    sid = rev = None
    service_http = False

    for name, value in RuleManager._split_options(options_text[:-1].strip()):
        if name == "content":
            items.append(Item("content", value.strip()))
        elif name in CONTENT_FLAGS:
            _last_content(items, name).nocase = True
        elif name in CONTENT_NUMBERS:
            item = _last_content(items, name)
            item.numbers = item.numbers or {}
            item.numbers[name] = _number(name, value)
        elif name == "fast_pattern":
            _last_content(items, name).fast_pattern = True
        elif name in BUFFER_MODIFIERS:
            item = _last_content(items, name)
            if item.buffer_set:
                raise Skip("content có hai buffer modifier")
            item.buffer, item.buffer_set = BUFFER_MODIFIERS[name], True
        elif name == "pcre":
            text, buffer = _convert_pcre(value)
            items.append(Item("pcre", text, buffer))
        elif name == "flow":
            tokens = [t.strip() for t in value.split(",") if t.strip() and t.strip() not in IGNORED_FLOW_TOKENS]
            kept["flow"].append(",".join(tokens))
        elif name in PASSTHROUGH:
            passthrough.append(f"{name}:{value};")
        elif name in ("msg", "classtype", "priority"):
            kept[name].append(value)
        elif name == "reference":
            kept["reference"].append(value)
        elif name == "metadata":
            service_http = service_http or bool(re.search(r"\bservice\s+(?:\w+,\s*)*http\b", value))
        elif name == "sid":
            sid = _number(name, value)
        elif name == "rev":
            rev = _number(name, value)
        elif name == "gid":
            if value.strip() != "1":
                raise Skip("gid khác 1")
        else:
            raise Skip(f"option {name} chưa hỗ trợ")

    if sid is None or not kept["msg"]:
        raise Skip("thiếu sid hoặc msg")
    if not any(i.kind in ("content", "pcre") for i in items):
        raise Skip("không có content hoặc pcre (sẽ báo trên mọi gói)")
    if sid >= CUSTOM_SID_MIN:
        raise Skip("SID nằm trong dải rule tự viết")

    # distance/within chỉ có nghĩa khi tương đối với match trước cùng buffer
    for index, item in enumerate(items):
        if item.kind == "content" and item.numbers and ({"distance", "within"} & set(item.numbers)):
            if index == 0 or items[index - 1].buffer != item.buffer:
                raise Skip("distance/within khác buffer với match trước")

    parts = [f"msg:{kept['msg'][0]};"]
    parts += [f"flow:{kept['flow'][0]};"] if kept["flow"] and kept["flow"][0] else []
    parts += [p for p in passthrough if not p.startswith("detection_filter")]
    current = PKT_DATA
    for item in items:
        if item.buffer != current:
            parts.append(f"{_sticky(item.buffer)};")
            current = item.buffer
        parts.append(f"{_content_text(item) if item.kind == 'content' else 'pcre:' + item.value};")
    parts += [p for p in passthrough if p.startswith("detection_filter")]
    if service_http or any(i.buffer[0].startswith("http_") for i in items):
        parts.append("service:http;")
    parts += [f"reference:{ref};" for ref in kept["reference"]]
    classtype = kept["classtype"][0].strip() if kept["classtype"] else ""
    if classtype:
        parts.append(f"classtype:{classtype};")
    priority = kept["priority"][0].strip() if kept["priority"] else str(CLASSTYPE_PRIORITY.get(classtype, DEFAULT_PRIORITY))
    parts.append(f"priority:{priority};")
    parts.append(f"sid:{sid};")
    parts.append(f"rev:{rev or 1};")

    rule = f"{header.strip()} ({' '.join(parts)})"
    try:
        parsed = manager.parse_rule_line(rule)
    except Exception as e:
        raise Skip(f"parse lỗi: {str(e)[:40]}")
    if parsed is None or parsed.unsupported_options:
        raise Skip("parse không sạch")
    return sid, kept["msg"][0].strip('"'), rule


def target_file(msg: str) -> str:
    """Chọn file đích theo tiền tố msg."""
    first = msg.split()[0] if msg.split() else ""
    if first.startswith(WEB_PREFIXES):
        return "community-web"
    family = first.split("-")[0]
    if family in MALWARE_FAMILIES:
        return "community-malware"
    if family in SERVER_FAMILIES:
        return "community-server"
    return "community-protocol"


def convert_file(source: Path, manager: RuleManager) -> Tuple[Dict[str, List[Tuple[int, str]]], Counter]:
    """Đọc bộ rule Snort 2, trả về {file: [(sid, rule)]} và thống kê lý do loại."""
    result: Dict[str, List[Tuple[int, str]]] = {name: [] for name in OUTPUT_FILES}
    skipped: Counter = Counter()
    seen = set()
    for raw in source.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        commented = COMMENTED_RULE.match(line)
        if not line or (line.startswith("#") and not commented):
            continue
        try:
            sid, msg, rule = convert_line(commented.group(1) if commented else line, manager)
            if sid in DENY_SIDS:
                raise Skip("nằm trong DENY_SIDS")
            if sid in seen:
                raise Skip("SID trùng")
        except Skip as e:
            skipped[str(e)] += 1
            continue
        seen.add(sid)
        result[target_file(msg)].append((sid, rule))
    return result, skipped


def render(name: str, rules: List[Tuple[int, str]]) -> str:
    body = "\n".join(rule for _, rule in sorted(rules))
    return FILE_HEADER.format(name=name) + "\n" + body + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Chuyển rule Snort 2 community sang cú pháp Snort 3 của engine")
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    setup_logging()
    source, out = Path(args.source), Path(args.out)
    if not source.exists():
        logger.error("Không thấy file nguồn %s", source)
        return 1
    manager = RuleManager(str(out))
    result, skipped = convert_file(source, manager)
    for name in OUTPUT_FILES:
        (out / f"{name}.rules").write_text(render(name, result[name]), encoding="utf-8", newline="\n")
    total = sum(len(rules) for rules in result.values())
    logger.info("Đã chuyển %d rule: %s", total, ", ".join(f"{n} {len(r)}" for n, r in result.items()))
    for reason, count in skipped.most_common():
        logger.info("Loại %d rule: %s", count, reason)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
