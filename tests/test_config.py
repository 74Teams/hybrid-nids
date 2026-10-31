import pytest
import yaml

from nids import config


def _ghi(path, data):
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


@pytest.fixture
def paths(tmp_path, monkeypatch):
    thuc = tmp_path / "settings.yaml"
    mau = tmp_path / "settings.example.yaml"
    monkeypatch.setattr(config, "DEFAULT_SETTINGS_PATH", thuc)
    monkeypatch.setattr(config, "EXAMPLE_SETTINGS_PATH", mau, raising=False)
    return thuc, mau


def test_falls_back_to_example_when_settings_missing(paths):
    _, mau = paths
    _ghi(mau, {"database": {"password": ""}})
    assert config.load_settings() == {"database": {"password": ""}}


def test_real_settings_win_over_example(paths):
    thuc, mau = paths
    _ghi(mau, {"a": 1})
    _ghi(thuc, {"b": 2})
    assert config.load_settings() == {"b": 2}
    thuc.write_text("", encoding="utf-8")
    assert config.load_settings() == {}


def test_missing_explicit_path_still_raises(paths, tmp_path):
    _, mau = paths
    _ghi(mau, {"a": 1})
    with pytest.raises(FileNotFoundError):
        config.load_settings(tmp_path / "x.yaml")


def test_env_password_overrides_empty_example_password(monkeypatch):
    monkeypatch.setitem(config.SETTINGS, "database", {"type": "mysql", "password": ""})
    monkeypatch.setenv("NIDS_DB_PASSWORD", "p@ss")
    assert "p%40ss" in config.get_db_url()


def test_example_file_has_no_password():
    data = yaml.safe_load(
        (config.ROOT_DIR / "config" / "settings.example.yaml").read_text(encoding="utf-8")
    )
    assert not data["database"]["password"]
