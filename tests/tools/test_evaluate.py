from datetime import datetime, timezone

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap

import nids.engine.decoder as decoder
from tools.cic.labels import BENIGN, load_labels
from tools.eval import evaluate as ev
from tools.eval import metrics
from tools.eval.runner import RuleLoadError, build_variables, default_config, load_rules

SQLI_SID = 1000001
T0 = datetime(2017, 7, 7, 17, 10, 5, tzinfo=timezone.utc).timestamp()   # 14:10:05 ADT
HEADER = " Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Label\n"


def flow(src, sport, dst, dport, first=0.0, last=1.0, alert_count=0, label=BENIGN, protocol="TCP"):
    return {"protocol": protocol, "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
            "first_seen": first, "last_seen": last, "alert_count": alert_count, "eval_label": label}


def alert(src, sport, dst, dport, ts, sid=1, source="RULE_ENGINE", msg="m", protocol="TCP"):
    return {"timestamp": ts, "sid": sid, "source_type": source, "msg": msg, "severity": 2, "src_ip": src,
            "src_port": sport, "dst_ip": dst, "dst_port": dport, "protocol": protocol}


# ── Quy tắc EXCLUDED ────────────────────────────────────────────────────────

def test_test_chunk_excludes_bot_flows_of_other_hosts():
    c2 = "205.174.165.73"
    assert metrics.evaluation_label("Bot", flow("192.168.10.9", 1, c2, 8080), "test", ["192.168.10.5"]) == "EXCLUDED"
    assert metrics.evaluation_label("Bot", flow("192.168.10.5", 1, c2, 8080), "test", ["192.168.10.5"]) == "Bot"
    # traffic bình thường của máy nhiễm khác vẫn được tính
    assert metrics.evaluation_label(BENIGN, flow("192.168.10.9", 1, "8.8.8.8", 53), "test", ["192.168.10.5"]) == BENIGN


def test_dev_chunk_excludes_every_flow_of_test_hosts():
    hosts = ["192.168.10.5"]
    assert metrics.evaluation_label(BENIGN, flow("192.168.10.5", 1, "8.8.8.8", 53), "dev", hosts) == "EXCLUDED"
    assert metrics.evaluation_label("PortScan", flow("172.16.0.1", 1, "192.168.10.50", 22), "dev", hosts) == "PortScan"


# ── Ghép cảnh báo với flow ──────────────────────────────────────────────────

def test_rule_alert_attaches_to_the_flow_alive_at_that_time():
    flows = [flow("10.0.0.5", 50000, "10.0.0.9", 80, 0, 10, label="WebAttack"),
             flow("10.0.0.5", 50000, "10.0.0.9", 80, 100, 110, label=BENIGN)]
    alerts = [alert("10.0.0.9", 80, "10.0.0.5", 50000, 5.0),       # chiều ngược vẫn cùng flow
              alert("10.0.0.5", 50000, "10.0.0.9", 80, 105.0),
              alert("10.0.0.5", 50000, "10.0.0.9", 80, 50.0)]       # giữa hai flow: không có flow nào
    metrics.attach_alerts(flows, alerts)
    assert [a["label"] for a in alerts] == ["WebAttack", BENIGN, metrics.UNMATCHED]
    assert [a["flow"] for a in alerts] == [0, 1, None]


def test_anomaly_alert_needs_the_same_ip_pair_as_an_attack_flow():
    c2 = "205.174.165.73"
    flows = [flow("192.168.10.9", 1, c2, 8080, 0, 1, label="Bot"),
             flow("192.168.10.9", 2, "8.8.8.8", 53, 0, 1, label=BENIGN)]
    alerts = [alert("192.168.10.9", 2, "8.8.8.8", 53, 10.0, sid=None, source="ANOMALY"),   # traffic thường của máy nhiễm
              alert(c2, 8080, "192.168.10.9", 1, 30.0, sid=None, source="ANOMALY"),
              alert(c2, 8080, "192.168.10.9", 1, 500.0, sid=None, source="ANOMALY")]       # quá ±60 giây
    metrics.attach_alerts(flows, alerts)
    assert [a["label"] for a in alerts] == [BENIGN, "Bot", BENIGN]


def test_anomaly_alert_on_test_host_in_dev_is_excluded():
    alerts = [alert("192.168.10.5", 1, "8.8.8.8", 53, 0.0, sid=None, source="ANOMALY")]
    metrics.attach_alerts([], alerts, "dev", ["192.168.10.5"])
    assert alerts[0]["label"] == "EXCLUDED"


# ── Tính số liệu ────────────────────────────────────────────────────────────

def test_class_and_sid_metrics():
    flows = [flow("a", 1, "b", 2, alert_count=1, label="PortScan"), flow("a", 3, "b", 4, label="PortScan"),
             flow("c", 1, "d", 2, alert_count=2, label=BENIGN), flow("c", 3, "d", 4, label=BENIGN),
             flow("e", 1, "f", 2, label="UNLABELED")]
    classes = metrics.class_metrics(flows)
    assert classes["PortScan"] == {"flows": 2, "rule_flagged": 1, "rate": 0.5}
    assert classes[BENIGN]["rate"] == 0.5
    assert list(classes)[0] == BENIGN and list(classes)[-1] == "UNLABELED"

    alerts = [dict(alert("a", 1, "b", 2, 0.5, sid=7), label="PortScan", flow=0),
              dict(alert("c", 1, "d", 2, 0.5, sid=7), label=BENIGN, flow=2),
              dict(alert("c", 1, "d", 2, 0.6, sid=7), label=BENIGN, flow=2)]
    row = metrics.sid_metrics(alerts, {7: 10})[0]
    assert (row["sid"], row["alerts"], row["tp"], row["fp"], row["raw_matches"]) == (7, 3, 1, 2, 10)
    assert row["precision"] == pytest.approx(1 / 3)
    assert row["top_fp"] == [("c → d:2", 2)]


# ── Chạy trọn vẹn trên pcap tự dựng ─────────────────────────────────────────

def tcp(src, sport, dst, dport, flags, seq, t, payload=b""):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq)
    if payload:
        p = p / Raw(payload)
    p.time = T0 + t
    return p


def connection(client, server, payload, t):
    request = tcp(*client, *server, "PA", 1001, t + 0.03, payload)
    return [tcp(*client, *server, "S", 1000, t), tcp(*server, *client, "SA", 9000, t + 0.01),
            tcp(*client, *server, "A", 1001, t + 0.02), request]


@pytest.fixture
def lab(tmp_path):
    attack = connection(("10.0.0.5", 50000), ("10.0.0.9", 80), b"GET /?q=union+select+1 HTTP/1.1\r\nHost: v\r\n\r\n", 0)
    normal = connection(("10.0.0.6", 50001), ("10.0.0.9", 80), b"GET /index.html HTTP/1.1\r\nHost: v\r\n\r\n", 1)
    wrpcap(str(tmp_path / "c.pcap"), attack + normal)
    rows = [("10.0.0.5", 50000, "10.0.0.9", 80, 6, "7/7/2017 2:10", "Web Attack \x96 Sql Injection"),
            ("10.0.0.6", 50001, "10.0.0.9", 80, 6, "7/7/2017 2:10", "BENIGN")]
    csv = tmp_path / "Friday-test.csv"
    csv.write_bytes((HEADER + "".join(",".join(map(str, r)) + "\n" for r in rows)).encode("latin-1"))
    manifest = {"day": "friday", "split_dir": str(tmp_path), "bot_hosts": [], "bot_test_hosts": [],
                "chunks": [{"file": "c.pcap", "set": "dev", "start_adt": "14:10", "first_ts": T0,
                            "last_ts": T0 + 2, "packets": 8}]}
    return manifest, load_labels([csv]), tmp_path


def run(lab, overrides=None):
    manifest, index, _ = lab
    return ev.evaluate(manifest, manifest["chunks"], index, default_config(overrides), jobs=1)


def test_end_to_end_counts_one_true_positive(lab):
    result = run(lab)
    assert result["funnel"]["total"] == 8 and result["funnel"]["analyzed"] == 8
    assert result["classes"]["WebAttack"] == {"flows": 1, "rule_flagged": 1, "rate": 1.0}
    assert result["classes"][BENIGN]["rule_flagged"] == 0
    sqli = next(r for r in result["sids"] if r["sid"] == SQLI_SID)
    assert (sqli["tp"], sqli["fp"]) == (1, 0)
    assert result["sources"]["RULE_ENGINE"]["precision"] == 1.0


def test_home_net_override_keeps_http_ports_rules(lab):
    default_count = len(load_rules("rules", build_variables()).rules)
    result = run(lab, {"HOME_NET": "10.0.0.0/8"})
    assert result["run"]["rules_loaded"] == default_count
    assert any(r["sid"] == SQLI_SID and r["tp"] == 1 for r in result["sids"])


def test_result_does_not_depend_on_local_settings(lab, monkeypatch):
    # máy khác có HTTP_PORTS lạ trong settings.yaml: bộ đo vẫn dùng biến mặc định
    monkeypatch.setattr(decoder, "HTTP_PORTS", frozenset({9999}))
    result = run(lab)
    assert any(r["sid"] == SQLI_SID and r["tp"] == 1 for r in result["sids"])
    assert decoder.HTTP_PORTS == frozenset({9999})   # bộ đo trả lại giá trị cũ sau khi chạy


def test_broken_rule_stops_the_run(tmp_path):
    (tmp_path / "bad.rules").write_text(
        'alert tcp any any -> any $KHONG_CO_BIEN (msg:"x"; content:"abc"; sid:2999999; rev:1;)\n', encoding="utf-8")
    with pytest.raises(RuleLoadError):
        load_rules(str(tmp_path), build_variables())


# ── Dòng lệnh ───────────────────────────────────────────────────────────────

def test_parse_overrides():
    assert ev.parse_overrides(["HOME_NET=10.0.0.0/8", " A = b "]) == {"HOME_NET": "10.0.0.0/8", "A": "b"}
    with pytest.raises(ValueError):
        ev.parse_overrides(["HOME_NET"])


def test_select_chunks():
    manifest = {"chunks": [{"start_adt": "09:09", "set": "test"}, {"start_adt": "09:19", "set": "dev"}]}
    assert [c["start_adt"] for c in ev.select_chunks(manifest, "dev", None)] == ["09:19"]
    assert [c["start_adt"] for c in ev.select_chunks(manifest, "dev", ["09:09"])] == ["09:09"]
    with pytest.raises(ValueError):
        ev.select_chunks(manifest, "dev", ["10:00"])


def test_main_refuses_test_set_without_flag(lab, tmp_path):
    import json
    manifest, _, folder = lab
    manifest["chunks"][0]["set"] = "test"
    path = tmp_path / "m.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert ev.main(["--manifest", str(path), "--labels-dir", str(folder), "--set", "test", "--name", "x"]) == 2


def test_main_writes_report(lab, tmp_path):
    import json
    manifest, _, folder = lab
    path = tmp_path / "m.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    code = ev.main(["--manifest", str(path), "--labels-dir", str(folder), "--name", "thu", "--jobs", "1",
                    "--report-dir", str(tmp_path / "r"), "--data-dir", str(tmp_path / "d")])
    assert code == 0
    report = (tmp_path / "r" / "thu.md").read_text(encoding="utf-8")
    assert "# Kết quả đo: thu" in report and "| WebAttack | 1 | 1 | 100,0% |" in report
    assert json.loads((tmp_path / "d" / "thu.json").read_text(encoding="utf-8"))["funnel"]["total"] == 8
