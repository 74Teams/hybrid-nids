"""API quản lý rule: category, override SID, custom.rules; thao tác ghi cần X-API-Key."""
import pytest
from fastapi.testclient import TestClient

from nids.config import SETTINGS

KEY = {"X-API-Key": "secret"}


def rule(sid):
    return f'alert tcp any any -> any 80 (msg:"r{sid}"; content:"c{sid}"; sid:{sid}; rev:1;)'


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    (tmp_path / "web.rules").write_text(rule(1000001) + "\n" + rule(1000002) + "\n", encoding="utf-8")
    (tmp_path / "dos.rules").write_text(rule(1000200) + "\n# " + rule(1000201) + "\n", encoding="utf-8")
    (tmp_path / "custom.rules").write_text("# rule tự viết\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "community.rules").write_text(rule(500) + "\n", encoding="utf-8")
    monkeypatch.setitem(SETTINGS.setdefault("detection", {}), "rules_dir", str(tmp_path))
    monkeypatch.setenv("NIDS_API_KEY", "secret")
    return tmp_path


@pytest.fixture
def client(rules_dir):
    from nids.api.main import app
    return TestClient(app)


def active(client):
    return {r["sid"] for r in client.get("/api/rules/?enabled=true").json()}


def test_list_has_category_and_state(client):
    rules = {r["sid"]: r for r in client.get("/api/rules/").json()}
    assert rules[1000201]["category"] == "dos" and not rules[1000201]["enabled"]
    assert not rules[1000201]["default_enabled"] and not rules[1000201]["overridden"]
    assert rules[500]["category"] == "vendor/community" and not rules[500]["enabled"]
    assert {r["sid"] for r in client.get("/api/rules/?category=dos").json()} == {1000200, 1000201}
    assert [r["sid"] for r in client.get("/api/rules/?q=r1000002").json()] == [1000002]
    assert client.get("/api/rules/?category=nope").status_code == 404


def test_categories_toggle(client):
    cats = {c["name"]: c for c in client.get("/api/rules/categories").json()}
    assert cats["custom"]["editable"] and cats["vendor/community"]["vendor"]
    resp = client.put("/api/rules/categories", json={"enabled": ["web", "vendor/community"]}, headers=KEY)
    assert resp.status_code == 200 and resp.json()["reload"] == "pending"
    assert active(client) == {1000001, 1000002, 500}
    assert client.put("/api/rules/categories", json={"enabled": ["../etc"]}, headers=KEY).status_code == 400


def test_apply_sids_and_overridden_flag(client):
    resp = client.post("/api/rules/sids", json={"enable": [1000201], "disable": [1000001]}, headers=KEY)
    assert resp.status_code == 200
    assert active(client) == {1000002, 1000200, 1000201}
    rules = {r["sid"]: r for r in client.get("/api/rules/").json()}
    assert rules[1000001]["overridden"] and rules[1000201]["overridden"] and not rules[1000002]["overridden"]
    assert client.post("/api/rules/sids", json={"disable": [42]}, headers=KEY).status_code == 400
    assert client.post("/api/rules/sids", json={"enable": [1], "disable": [1]}, headers=KEY).status_code == 400


def test_reset_current_and_all(client):
    client.post("/api/rules/sids", json={"enable": [1000201], "disable": [1000001]}, headers=KEY)
    assert client.post("/api/rules/sids/reset", json={"category": "dos"}, headers=KEY).status_code == 200
    assert active(client) == {1000002, 1000200}
    assert client.post("/api/rules/sids/reset", json={}, headers=KEY).status_code == 200
    assert active(client) == {1000001, 1000002, 1000200}
    assert client.post("/api/rules/sids/reset", json={"category": "nope"}, headers=KEY).status_code == 404


def test_enable_all_disable_all_with_vendor_path(client):
    assert client.post("/api/rules/categories/dos/all", json={"enabled": True}, headers=KEY).status_code == 200
    assert {1000200, 1000201} <= active(client)
    assert client.post("/api/rules/categories/dos/all", json={"enabled": False}, headers=KEY).status_code == 200
    assert not {1000200, 1000201} & active(client)
    assert client.post("/api/rules/categories/vendor/community/all", json={"enabled": False},
                       headers=KEY).status_code == 200
    assert client.post("/api/rules/categories/../web/all", json={"enabled": False}, headers=KEY).status_code == 404


def test_custom_read_and_valid_write(client, rules_dir):
    assert client.get("/api/rules/custom").text == "# rule tự viết\n"
    text = rule(2000001) + "\n" + 'alert tcp any any -> any 80 (msg:"w"; content:"q"; nocase; sid:2000002; rev:1;)'
    resp = client.put("/api/rules/custom", content=text.encode(), headers=KEY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["rules"] == 2 and body["reload"] == "pending"
    assert body["warnings"] == [{"line": 2, "warning": "option chưa hỗ trợ: nocase"}]
    assert {2000001, 2000002} <= active(client)
    assert (rules_dir / "custom.rules.bak").read_text(encoding="utf-8") == "# rule tự viết\n"
    assert client.get("/api/rules/custom").text.endswith("\n")


def test_custom_invalid_write_reports_lines_and_keeps_file(client, rules_dir):
    text = "\n".join([
        "# ok",
        rule(2000001),
        'alert tcp any any -> any 80 (msg:"x"; sid:2000003; rev:1)',  # thiếu ';' cuối
        rule(1000001).replace("1000001", "1000999"),                  # ngoài dải custom
        rule(2000001),                                                # trùng trong file
        "không phải rule",
    ])
    resp = client.put("/api/rules/custom", content=text.encode(), headers=KEY)
    assert resp.status_code == 422
    assert [e["line"] for e in resp.json()["detail"]["errors"]] == [3, 4, 5, 6]
    assert (rules_dir / "custom.rules").read_text(encoding="utf-8") == "# rule tự viết\n"


def test_custom_sid_clash_with_other_category(client):
    resp = client.put("/api/rules/custom", content=rule(2000000).replace("2000000", "1000001").encode(), headers=KEY)
    assert resp.status_code == 422


def test_custom_too_large(client):
    resp = client.put("/api/rules/custom", content=b"#" * 1_000_001, headers=KEY)
    assert resp.status_code == 413


@pytest.mark.parametrize("method,path,payload", [
    ("put", "/api/rules/categories", {"json": {"enabled": []}}),
    ("post", "/api/rules/sids", {"json": {"disable": [1000001]}}),
    ("post", "/api/rules/sids/reset", {"json": {}}),
    ("post", "/api/rules/categories/dos/all", {"json": {"enabled": False}}),
    ("put", "/api/rules/custom", {"content": b""}),
])
def test_writes_require_api_key(client, rules_dir, monkeypatch, method, path, payload):
    assert getattr(client, method)(path, **payload).status_code == 401
    assert getattr(client, method)(path, headers={"X-API-Key": "wrong"}, **payload).status_code == 401
    monkeypatch.delenv("NIDS_API_KEY")
    assert getattr(client, method)(path, headers=KEY, **payload).status_code == 503
    assert not (rules_dir / "state.yaml").exists()
