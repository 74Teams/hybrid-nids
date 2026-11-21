"""Bộ phân tích AI của sensor: gộp theo đợt, tự tắt khi mô hình hỏng, hàng đợi đầy không chặn, không làm sập luồng."""
import threading

import numpy as np
import pytest

from nids.ai.features import FEATURE_NAMES
from nids.ai.worker import AITrafficWorker, load_bundle
from nids.engine.flow import Flow

BAD_PORT = 9999
PORT_COLUMN = FEATURE_NAMES.index("dst_port")


class FakeForest:
    """Chấm PortScan cho flow tới cổng BAD_PORT, còn lại BENIGN."""
    classes_ = np.array(["BENIGN", "PortScan"])

    def predict_proba(self, X):
        scan = (X[:, PORT_COLUMN] == BAD_PORT).astype(float) * 0.9
        return np.stack([1 - scan, scan], axis=1)


def make_bundle(rf=None):
    return {"rf": rf or FakeForest(), "feature_names": list(FEATURE_NAMES),
            "thresholds": {"per_class": {"PortScan": 0.5}},
            "context": {"window": 60.0, "short_window": 5.0, "max_tracked": 1000, "max_per_ip": 1000}}


def make_flow(src="10.0.0.9", dport=BAD_PORT, ts=100.0) -> Flow:
    return Flow(protocol="TCP", src_ip=src, src_port=40000, dst_ip="10.0.0.1", dst_port=dport,
                first_seen=ts, last_seen=ts + 0.001, fwd_packets=1, bwd_packets=1, fwd_bytes=60, bwd_bytes=60,
                syn_count=1, rst_count=1)


def run(worker: AITrafficWorker, flows) -> None:
    worker.start()
    worker.submit(flows)
    worker.close()


def new_worker(alerts, **config):
    return AITrafficWorker(make_bundle(), alerts.append, {"batch_wait": 0.05, **config})


def test_one_alert_per_attack_wave():
    alerts = []
    run(new_worker(alerts), [make_flow(dport=BAD_PORT, ts=100 + i * 0.01) for i in range(300)])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["source_type"] == "AI_ENGINE" and alert["sid"] is None
    assert alert["classtype"] == "PortScan" and alert["severity"] == 2
    assert alert["src_ip"] == "10.0.0.9"
    assert "300 flow" in alert["matched_content"] or "flow bị chấm" in alert["matched_content"]


def test_benign_flows_raise_no_alert():
    alerts = []
    run(new_worker(alerts), [make_flow(dport=443, ts=100 + i) for i in range(50)])
    assert alerts == []


def test_alert_repeats_after_suppress_window():
    alerts = []
    worker = new_worker(alerts, suppress_seconds=60, batch_size=1)
    run(worker, [make_flow(ts=100), make_flow(ts=130), make_flow(ts=200)])
    assert len(alerts) == 2   # flow thứ hai nằm trong cửa sổ 60s của lần báo đầu, flow thứ ba thì không


def test_ignored_source_is_not_scored():
    alerts = []
    worker = new_worker(alerts, ignore_ips=["10.0.0.9"])
    run(worker, [make_flow(src="10.0.0.9"), make_flow(src="10.0.0.8")])
    assert [a["src_ip"] for a in alerts] == ["10.0.0.8"]


def test_close_scores_everything_still_queued():
    alerts = []
    worker = new_worker(alerts, batch_size=10, batch_wait=5.0)
    worker.start()
    worker.submit([make_flow(src=f"10.1.0.{i}") for i in range(100)])
    worker.close()
    assert worker.scored == 100 and len(alerts) == 100


def test_full_queue_drops_flows_without_blocking():
    worker = new_worker([], queue_max_size=5)   # chưa start: không ai lấy flow ra
    worker.submit([make_flow(ts=i) for i in range(20)])
    assert worker.dropped == 15


def test_scoring_error_does_not_kill_thread():
    class Broken(FakeForest):
        calls = 0

        def predict_proba(self, X):
            Broken.calls += 1
            if Broken.calls == 1:
                raise RuntimeError("hỏng")
            return super().predict_proba(X)

    alerts = []
    worker = AITrafficWorker(make_bundle(Broken()), alerts.append, {"batch_size": 1, "batch_wait": 0.05})
    run(worker, [make_flow(src="10.0.0.1"), make_flow(src="10.0.0.2")])
    assert [a["src_ip"] for a in alerts] == ["10.0.0.2"]


def test_callback_error_does_not_kill_thread():
    seen = []

    def callback(alert):
        seen.append(alert["src_ip"])
        raise RuntimeError("CSDL lỗi")

    worker = AITrafficWorker(make_bundle(), callback, {"batch_size": 1, "batch_wait": 0.05})
    run(worker, [make_flow(src="10.0.0.1"), make_flow(src="10.0.0.2")])
    assert seen == ["10.0.0.1", "10.0.0.2"]


def test_disabled_or_missing_model_returns_none(tmp_path):
    assert AITrafficWorker.from_settings({"enabled": False}) is None
    assert AITrafficWorker.from_settings({"model_path": str(tmp_path / "missing-model.joblib")}) is None


def test_mismatched_features_disable_ai(tmp_path):
    import joblib
    bundle = make_bundle()
    bundle["feature_names"] = FEATURE_NAMES[:-1]
    path = tmp_path / "bad.joblib"
    joblib.dump(bundle, path)
    with pytest.raises(ValueError):
        load_bundle(str(path))
    assert AITrafficWorker.from_settings({"model_path": str(path)}) is None


def test_real_model_loads_and_scores_when_present():
    from pathlib import Path
    path = Path(__file__).resolve().parents[4] / "data" / "models" / "flow_model.joblib"
    if not path.is_file():
        pytest.skip("không có mô hình")
    worker = AITrafficWorker.from_settings({"model_path": str(path), "batch_wait": 0.05}, lambda a: None)
    assert worker is not None and "BENIGN" in worker.classes
    worker.start()
    worker.submit([make_flow(dport=443, ts=100 + i) for i in range(10)])
    worker.close()
    assert worker.scored == 10 and threading.active_count() >= 1
