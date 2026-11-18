from pathlib import Path

import joblib
import pytest

from tools.ai.demo_ai import ATTACKER, TYPO_USER, WEB_USERS, classify, load_bundle, scan_scenario

MODEL = Path("models/flow_model.joblib")
needs_model = pytest.mark.skipif(not MODEL.exists(), reason="chưa có models/flow_model.joblib (chạy tools.ai.train)")


def _flagged_by_source(results):
    stats = {}
    for flow, label in results:
        total, flagged = stats.get(flow.src_ip, (0, 0))
        stats[flow.src_ip] = (total + 1, flagged + (label != "BENIGN"))
    return stats


@needs_model
def test_scan_scenario_flags_the_scanner_but_not_normal_hosts():
    results = classify(scan_scenario(seconds=15), load_bundle(str(MODEL)))
    stats = _flagged_by_source(results)
    total, flagged = stats[ATTACKER]
    assert total > 5000 and flagged / total > 0.95
    for host in (TYPO_USER, *WEB_USERS):          # flow SYN rồi RST của người gõ nhầm giống hệt flow quét, nhưng không bị báo
        assert stats[host][1] == 0


@needs_model
def test_load_bundle_rejects_a_model_with_other_feature_names(tmp_path):
    bundle = joblib.load(MODEL)
    bundle["feature_names"] = bundle["feature_names"][:-1]
    path = tmp_path / "old.joblib"
    joblib.dump(bundle, path)
    with pytest.raises(ValueError, match="FEATURE_NAMES"):
        load_bundle(str(path))
