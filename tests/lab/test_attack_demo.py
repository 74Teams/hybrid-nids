"""Mỗi đòn trong lab/attacker/attack_demo.py phải khiến NIDS bắn đúng SID đã khai báo."""
import pytest

from lab.attacker.attack_demo import GROUPS, attack_packets
from nids.engine.detector import DetectionEngine
from nids.engine.rule_manager import RuleManager
from nids.engine.decoder import PacketDecoder

TARGET = "10.0.0.5"
SRC = "192.168.1.77"


@pytest.fixture(scope="module")
def rule_manager():
    manager = RuleManager("rules")
    manager.load_all_rules()
    return manager


def _attacks(group):
    return GROUPS[group](TARGET, SRC)


@pytest.mark.parametrize("group", list(GROUPS))
def test_every_attack_triggers_its_expected_sids(rule_manager, group):
    engine = DetectionEngine(rule_manager, enable_threshold=False)
    for attack in _attacks(group):
        fired = set()
        for pkt in attack_packets(attack, TARGET, SRC):
            decoded = PacketDecoder.decode(pkt)
            assert decoded is not None, attack.name
            fired.update(r.sid for r in engine.evaluate_packet(decoded))
        missing = set(attack.sids) - fired
        assert not missing, f"[{group}] '{attack.name}' thiếu SID {sorted(missing)} (đã bắn: {sorted(fired)})"


def test_all_attack_sids_exist_in_ruleset(rule_manager):
    for group in GROUPS:
        for attack in _attacks(group):
            assert set(attack.sids) <= set(rule_manager.rules_by_sid), attack.name


def test_every_rule_is_covered_by_an_attack(rule_manager):
    covered = {sid for group in GROUPS for attack in _attacks(group) for sid in attack.sids}
    assert not set(rule_manager.rules_by_sid) - covered, "Rule chưa có đòn trình diễn"
