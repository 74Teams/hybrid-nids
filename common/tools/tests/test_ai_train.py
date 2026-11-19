import numpy as np
import pandas as pd
import pytest

from tools.ai import train
from tools.ai.train import (ATTACK_LABELS, align_proba, apply_threshold, assign_folds, attach_folds,
                            choose_thresholds, make_folds, out_of_fold, pair_report, parse_rf_params,
                            parse_scale, scale_context)

CLASSES = np.array(["BENIGN", "DoS", "PortScan"])


def test_apply_threshold_per_class():
    proba = np.array([[0.2, 0.7, 0.1],      # DoS, 0,7
                      [0.2, 0.1, 0.7],      # PortScan, 0,7
                      [0.9, 0.05, 0.05]])   # BENIGN
    pred = apply_threshold(proba, CLASSES, {"DoS": 0.8, "PortScan": 0.6})
    assert list(pred) == ["BENIGN", "PortScan", "BENIGN"]      # DoS dưới ngưỡng riêng thành BENIGN
    assert list(apply_threshold(proba, CLASSES, 0.5)) == ["DoS", "PortScan", "BENIGN"]


def test_choose_thresholds_splits_fpr_and_falls_back():
    # 100 BENIGN: 4 flow bị đoán DoS với xác suất 0,6 và 0,6 và 0,9 và 0,9; PortScan không bị đoán nhầm
    y = np.array(["BENIGN"] * 100)
    proba = np.tile([0.95, 0.03, 0.02], (100, 1))
    proba[0:2] = [0.3, 0.6, 0.1]
    proba[2:4] = [0.05, 0.9, 0.05]
    result = choose_thresholds(proba, CLASSES, y, target_fpr=0.01)      # mỗi lớp được 0,5% = 0,5 flow
    assert result["PortScan"] == 0.5          # không bị nhầm nên ngưỡng thấp nhất đã đạt
    assert result["DoS"] == 0.95              # không ngưỡng nào đưa số nhầm về 0 flow ở 0,5%: rơi về 0,95
    relaxed = choose_thresholds(proba, CLASSES, y, target_fpr=0.2)      # mỗi lớp được 10% = 10 flow
    assert relaxed["DoS"] == 0.5


def test_align_proba_fills_missing_class_with_zero():
    proba = np.array([[0.4, 0.6]])
    aligned = align_proba(proba, ["BENIGN", "PortScan"], CLASSES)      # mô hình không có DoS
    assert aligned.tolist() == [[0.4, 0.0, 0.6]]


def _toy(n_per_fold=6):
    rows = []
    for fold in range(4):
        for i in range(n_per_fold):
            attack = i % 2 == 0
            rows.append({"fold": fold, "x": 1.0 + 0.01 * i if attack else -1.0 - 0.01 * i,
                         "y": "DoS" if attack else "BENIGN"})
    return pd.DataFrame(rows)


def test_out_of_fold_each_row_predicted_once_even_if_train_misses_a_class():
    df = _toy()
    df.loc[df["fold"] == 3, "y"] = "BENIGN"          # phần 3 không có DoS; khi phần 0 là validation, train vẫn có DoS
    df.loc[df["fold"].isin([1, 2, 3]), "y"] = "BENIGN"      # chỉ phần 0 có DoS: khi phần 0 làm validation, train thiếu DoS
    X = df[["x"]].to_numpy()
    y = df["y"].to_numpy()
    fold = df["fold"].to_numpy()
    params = dict(n_estimators=5, random_state=0)
    proba = out_of_fold(X, y, fold, np.ones(len(df), bool), np.ones(len(df), bool), CLASSES[:2], params)
    assert not np.isnan(proba).any()                          # mỗi flow có đúng một hàng xác suất
    assert proba.shape == (len(df), 2)
    assert np.allclose(proba.sum(axis=1), 1.0)
    assert proba[fold == 0][:, 1].max() == 0.0                # train thiếu DoS: cột DoS bằng 0, không lệch cột


def test_out_of_fold_train_mask_does_not_change_validation_rows():
    df = _toy()
    X, y, fold = df[["x"]].to_numpy(), df["y"].to_numpy(), df["fold"].to_numpy()
    everything = np.ones(len(df), bool)
    drop_some = everything.copy()
    drop_some[(y == "BENIGN") & (np.arange(len(df)) % 3 == 0)] = False        # chỉ bớt ở phần train
    params = dict(n_estimators=5, random_state=0)
    full = out_of_fold(X, y, fold, everything, everything, np.array(["BENIGN", "DoS"]), params)
    filtered = out_of_fold(X, y, fold, drop_some, everything, np.array(["BENIGN", "DoS"]), params)
    assert not np.isnan(full).any() and not np.isnan(filtered).any()          # validation vẫn đủ mọi hàng


def _pairs_frame(rows):
    frame = pd.DataFrame(rows, columns=["day", "src_ip", "dst_ip", "block", "eval_label"])
    frame["pair"] = np.where(frame["src_ip"] < frame["dst_ip"], frame["src_ip"] + "|" + frame["dst_ip"],
                             frame["dst_ip"] + "|" + frame["src_ip"])
    return frame


def test_pair_report_counts_detected_groups_and_ignores_small_ones():
    rows = ([("fri", "1.1.1.1", "2.2.2.2", 1, "PortScan")] * 10            # nhóm đủ 10 flow
            + [("fri", "2.2.2.2", "1.1.1.1", 1, "PortScan")] * 2           # chiều ngược: cùng một cặp, cùng một nhóm
            + [("fri", "3.3.3.3", "4.4.4.4", 1, "PortScan")] * 10          # nhóm đủ flow nhưng không flow nào bị phát hiện
            + [("fri", "5.5.5.5", "6.6.6.6", 1, "PortScan")] * 3)          # nhóm nhỏ, bị loại
    frame = _pairs_frame(rows)
    pred = np.array(["PortScan"] + ["BENIGN"] * 11 + ["BENIGN"] * 10 + ["PortScan"] * 3, dtype=object)
    report = pair_report(frame, pred)["attack"]["PortScan"]
    assert report == {"groups": 2, "detected": 1, "small": 1}


def test_pair_report_false_pairs_only_count_all_benign_groups():
    rows = [("fri", "7.7.7.7", "8.8.8.8", 1, "BENIGN"), ("fri", "7.7.7.7", "8.8.8.8", 1, "BENIGN"),
            ("fri", "9.9.9.9", "8.8.8.8", 1, "BENIGN"),
            ("fri", "1.1.1.1", "2.2.2.2", 1, "PortScan"), ("fri", "1.1.1.1", "2.2.2.2", 1, "BENIGN")]
    pred = np.array(["DoS", "BENIGN", "BENIGN", "PortScan", "PortScan"], dtype=object)
    report = pair_report(_pairs_frame(rows), pred)
    assert report["false_pairs"] == 1          # chỉ nhóm 7.7.7.7|8.8.8.8; nhóm có tấn công không tính
    assert report["benign_pairs"] == 2


def _meta():
    rows = []
    for day in ("mon", "tue"):
        for block in range(8):
            for i in range(10):
                rows.append({"day": day, "first_seen": block * train.BLOCK_SECONDS + i,
                             "eval_label": "DoS" if block % 2 else "BENIGN"})
    return pd.DataFrame(rows)


def test_assign_folds_is_stable_and_whole_blocks_stay_together():
    first = assign_folds(_meta())
    again = assign_folds(_meta())
    assert first.equals(again)
    assert not first.duplicated(["day", "block"]).any()
    assert set(first["fold"]) <= set(range(train.N_FOLDS))
    without_dos = _meta()
    without_dos.loc[without_dos["eval_label"] == "DoS", "eval_label"] = "BENIGN"
    assert not assign_folds(without_dos).equals(first)      # chia ngay trên dữ liệu khác thì khác: vì thế phải lưu file


def test_attach_folds_rejects_unknown_block():
    folds = pd.DataFrame({"day": ["mon"], "block": [1], "fold": [0]})
    data = pd.DataFrame({"day": ["mon", "mon"], "block": [1, 2]})
    with pytest.raises(ValueError, match="không có trong folds.csv"):
        attach_folds(data, folds)
    assert attach_folds(data.iloc[:1], folds)["fold"].tolist() == [0]


def test_make_folds_refuses_to_overwrite(tmp_path):
    features = tmp_path / "features" / "mon"
    features.mkdir(parents=True)
    meta = _meta()
    meta = meta[meta["day"] == "mon"].assign(split="dev")
    meta.to_csv(features / "0000.csv.gz", index=False)
    target = tmp_path / "folds.csv"
    make_folds(str(tmp_path / "features"), target)
    assert target.exists() and len(pd.read_csv(target)) == 8
    with pytest.raises(ValueError, match="đã có"):
        make_folds(str(tmp_path / "features"), target)


def test_parse_rf_params_and_errors():
    params = parse_rf_params("max_depth=15,n_estimators=200,min_samples_leaf=5")
    assert (params["max_depth"], params["n_estimators"], params["min_samples_leaf"]) == (15, 200, 5)
    assert params["random_state"] == 42
    assert parse_rf_params("max_depth=None")["max_depth"] is None
    with pytest.raises(ValueError):
        parse_rf_params("khong_co=1")
    with pytest.raises(ValueError):
        parse_rf_params("max_depth")


def test_scale_context_needs_context_columns():
    X = np.ones((2, 2))
    with pytest.raises(ValueError, match="chưa có cột ngữ cảnh"):
        scale_context(X, ["a", "b"], np.array(["PortScan", "BENIGN"]), parse_scale("PortScan=0.1"))
    out = scale_context(np.array([[100.0, 1.0], [100.0, 1.0]]), ["src_flows_60s", "dst_port"],
                        np.array(["PortScan", "BENIGN"]), ("PortScan", 0.1))
    assert out.tolist() == [[10.0, 1.0], [100.0, 1.0]]
    assert scale_context(np.array([[3.0]]), ["src_flows_60s"], np.array(["PortScan"]), ("PortScan", 0.1))[0, 0] == 1.0


def test_main_reports_errors_instead_of_crashing(tmp_path):
    missing_folds = str(tmp_path / "missing-folds.csv")
    assert train.main(["--folds", missing_folds, "--no-save"]) == 2                    # chưa có folds.csv
    assert train.main(["--folds", missing_folds, "--drop-features", "dst_port"]) == 2   # thiếu --no-save
    assert train.main(["--folds", missing_folds, "--drop-features", "khong_co", "--no-save"]) == 2


def test_attack_labels_exclude_web_attack():
    assert "WebAttack" not in ATTACK_LABELS and "BENIGN" not in ATTACK_LABELS


def test_out_of_fold_collects_one_importance_vector_per_fold():
    df = _toy()
    X, y, fold = df[["x"]].to_numpy(), df["y"].to_numpy(), df["fold"].to_numpy()
    everything = np.ones(len(df), bool)
    importances = []
    out_of_fold(X, y, fold, everything, everything, np.array(["BENIGN", "DoS"]),
                dict(n_estimators=5, random_state=0), None, importances)
    assert len(importances) == 4 and all(len(vector) == 1 for vector in importances)

