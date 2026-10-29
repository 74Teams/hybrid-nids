"""Category (mỗi file .rules), bật/tắt theo file và override theo SID lưu trong rules/state.yaml."""
import pytest
import yaml

from nids.engine.rule_manager import RuleManager


def rule(sid, content="x"):
    return f'alert tcp any any -> any 80 (msg:"r{sid}"; content:"{content}{sid}"; sid:{sid}; rev:1;)'


@pytest.fixture
def rules_dir(tmp_path):
    (tmp_path / "web.rules").write_text(rule(1) + "\n" + rule(2) + "\n", encoding="utf-8")
    (tmp_path / "dos.rules").write_text(rule(10) + "\n# " + rule(11) + "\n# chỉ là comment\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "community.rules").write_text(rule(500) + "\n", encoding="utf-8")
    return tmp_path


def loaded(rules_dir):
    m = RuleManager(str(rules_dir))
    m.load_all_rules()
    return m


def write_state(rules_dir, state):
    (rules_dir / "state.yaml").write_text(yaml.safe_dump(state), encoding="utf-8")


def test_default_without_state_enables_root_files_only(rules_dir):
    m = loaded(rules_dir)
    assert set(m.rules_by_sid) == {1, 2, 10}
    assert m.enabled_categories == {"web", "dos"}
    cats = {c["name"]: c for c in m.list_categories()}
    assert cats["vendor/community"] == {"name": "vendor/community", "enabled": False, "rule_count": 1,
                                        "active_count": 0, "vendor": True, "editable": False}
    assert cats["dos"]["rule_count"] == 2 and cats["dos"]["active_count"] == 1


def test_commented_rule_is_default_disabled_and_tagged(rules_dir):
    m = loaded(rules_dir)
    r11 = next(r for r in m.all_rules() if r.sid == 11)
    assert r11.category == "dos" and not r11.default_enabled and not r11.enabled
    assert r11.raw_rule.startswith("alert")


def test_disabled_category_is_not_loaded(rules_dir):
    write_state(rules_dir, {"enabled_categories": ["web", "vendor/community"]})
    m = loaded(rules_dir)
    assert set(m.rules_by_sid) == {1, 2, 500}


def test_unknown_category_in_state_is_ignored(rules_dir, caplog):
    write_state(rules_dir, {"enabled_categories": ["web", "missing"]})
    assert set(loaded(rules_dir).rules_by_sid) == {1, 2}
    assert any("missing" in r.getMessage() for r in caplog.records)


def test_set_enabled_categories_persists_and_rejects_unknown(rules_dir):
    m = loaded(rules_dir)
    m.set_enabled_categories(["dos"])
    assert set(m.rules_by_sid) == {10}
    assert set(loaded(rules_dir).rules_by_sid) == {10}
    with pytest.raises(ValueError):
        m.set_enabled_categories(["../etc"])


def test_sid_overrides_and_minimal_state(rules_dir):
    m = loaded(rules_dir)
    m.set_sid_state(enable=[11], disable=[1])
    assert set(m.rules_by_sid) == {2, 10, 11}
    # Đặt về đúng mặc định thì override bị xoá
    m.set_sid_state(enable=[1])
    assert m.load_state()["sid_overrides"] == {"enable": [11], "disable": []}
    with pytest.raises(ValueError):
        m.set_sid_state(disable=[999])


def test_disabled_category_wins_over_override(rules_dir):
    m = loaded(rules_dir)
    m.set_sid_state(enable=[500])
    assert 500 not in m.rules_by_sid
    m.set_enabled_categories(["web", "dos", "vendor/community"])
    assert 500 in m.rules_by_sid


def test_reset_current_and_reset_all(rules_dir):
    m = loaded(rules_dir)
    m.set_sid_state(enable=[11], disable=[1])
    m.reset_overrides("dos")
    assert m.load_state()["sid_overrides"] == {"enable": [], "disable": [1]}
    m.reset_overrides()
    assert set(m.rules_by_sid) == {1, 2, 10}


def test_enable_all_and_disable_all_in_category(rules_dir):
    m = loaded(rules_dir)
    m.set_category_rules("dos", True)
    assert {10, 11} <= set(m.rules_by_sid)
    m.set_category_rules("dos", False)
    assert not {10, 11} & set(m.rules_by_sid)
    with pytest.raises(KeyError):
        m.set_category_rules("nope", True)


def test_override_for_missing_sid_is_kept(rules_dir):
    write_state(rules_dir, {"sid_overrides": {"enable": [], "disable": [777]}})
    m = loaded(rules_dir)
    m.set_sid_state(disable=[2])
    assert m.load_state()["sid_overrides"]["disable"] == [2, 777]


def test_state_is_written_atomically_without_leftover_tmp(rules_dir):
    m = loaded(rules_dir)
    m.set_sid_state(disable=[1])
    assert sorted(p.name for p in rules_dir.iterdir() if p.is_file()) == ["dos.rules", "state.yaml", "web.rules"]


def test_broken_state_falls_back_to_default(rules_dir):
    (rules_dir / "state.yaml").write_text("enabled_categories: [web\n", encoding="utf-8")
    assert set(loaded(rules_dir).rules_by_sid) == {1, 2, 10}


def test_signature_changes_when_state_changes(rules_dir):
    m = loaded(rules_dir)
    before = m.signature()
    m.set_sid_state(disable=[1])
    assert m.signature() != before


def test_duplicate_sid_across_files_logs_both_locations(rules_dir, caplog):
    (rules_dir / "zz.rules").write_text(rule(1, "y") + "\n", encoding="utf-8")
    assert loaded(rules_dir).rules_by_sid[1].category == "web"
    assert any("Bỏ qua SID trùng 1" in r.getMessage() and "web.rules" in r.getMessage() for r in caplog.records)


def test_repo_ruleset_default_loads_67_builtin_rules():
    m = loaded("rules")
    builtin = ["web-attack", "scan", "dos", "auth", "malware-c2", "recon"]  # theo dải SID 10000xx..10005xx
    assert sum(len(m.catalog[c]) for c in builtin) == 67
    assert all((r.sid - 1000000) // 100 == i for i, c in enumerate(builtin) for r in m.catalog[c])
