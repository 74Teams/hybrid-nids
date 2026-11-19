import argparse
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

from nids.logger import setup_logging
from tools.cic.labels import C2_CORRECTION_DAYS, C2_IP, find_label_files, group_label, parse_cic_timestamp

logger = logging.getLogger("nids.ai")

ID_COLUMNS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp", "Label"]
DROP_LABELS = {"Heartbleed", "Infiltration"}
BLOCK_SECONDS = 300   

def load_day(labels_dir: str, day: str) -> pd.DataFrame:
    """Đọc mọi file CSV của một ngày, chuẩn hoá tên cột, thêm cột `label` (lớp gộp) và `ts` (epoch UTC)."""
    frames = []
    for path in find_label_files(labels_dir, day):
        frame = pd.read_csv(path, encoding="latin-1", low_memory=False)
        frame.columns = [c.strip() for c in frame.columns]      # tên cột CSV có dấu cách ở đầu
        frame = frame.dropna(subset=["Label", "Timestamp"])
        logger.info("Đọc %d dòng từ %s", len(frame), path.name)
        frames.append(frame)
    data = pd.concat(frames, ignore_index=True)
    labels = {v: group_label(v) for v in data["Label"].unique()}
    data["label"] = data["Label"].map(labels)
    if day.lower() in C2_CORRECTION_DAYS:
        # CSV ghi BENIGN cho các flow gọi về máy điều khiển botnet ngoài khung giờ Bot (xem tools/cic/labels.py)
        to_c2 = data["Source IP"].str.strip().eq(C2_IP) | data["Destination IP"].str.strip().eq(C2_IP)
        fixed = to_c2 & data["label"].eq("BENIGN")
        data.loc[fixed, "label"] = "Bot"
        logger.info("Sửa %d dòng BENIGN của máy điều khiển botnet thành Bot", int(fixed.sum()))
    stamps = {v: parse_cic_timestamp(v) for v in data["Timestamp"].unique()}
    data["ts"] = data["Timestamp"].map(stamps)
    return data[~data["label"].isin(DROP_LABELS)].reset_index(drop=True)


def feature_matrix(data: pd.DataFrame) -> pd.DataFrame:
    """Bảng đặc trưng số: bỏ cột định danh, đổi chữ thành số, Infinity/NaN thành NaN."""
    columns = [c for c in data.columns if c not in ID_COLUMNS + ["label", "ts"] and not c.endswith(".1")]
    X = data[columns].apply(pd.to_numeric, errors="coerce")
    return X.replace([np.inf, -np.inf], np.nan)


def assign_sets(data: pd.DataFrame, manifest_path: str) -> pd.Series:
    """Gán dev/test cho mỗi dòng theo chunk 10 phút trong manifest; máy Bot để thi bị loại khỏi dev."""
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    chunks = manifest["chunks"]
    starts = np.array([c["first_ts"] for c in chunks])
    sets = np.array([c["set"] for c in chunks])
    position = np.clip(np.searchsorted(starts, data["ts"].to_numpy(), side="right") - 1, 0, len(chunks) - 1)
    result = pd.Series(sets[position], index=data.index)
    test_hosts = set(manifest.get("bot_test_hosts", []))
    touches_test_host = data["Source IP"].isin(test_hosts) | data["Destination IP"].isin(test_hosts)
    result[(result == "dev") & touches_test_host] = "excluded"
    return result


def report(y_true, y_pred, title: str) -> None:
    labels = sorted(set(y_true) | set(y_pred))
    logger.info("=== %s ===\n%s", title, classification_report(y_true, y_pred, digits=3, zero_division=0))
    matrix = pd.DataFrame(confusion_matrix(y_true, y_pred, labels=labels),
                          index=[f"thật {l}" for l in labels], columns=[f"đoán {l}" for l in labels])
    logger.info("Ma trận nhầm lẫn:\n%s", matrix.to_string())
    benign = np.asarray(y_true) == "BENIGN"
    if benign.any():
        fpr = (np.asarray(y_pred)[benign] != "BENIGN").mean()
        logger.info("FPR (BENIGN bị báo là tấn công): %.3f%%", 100 * fpr)


def main(argv=None) -> int:
    setup_logging("INFO")
    parser = argparse.ArgumentParser(description="Random Forest trên CSV CICFlowMeter (bài tập khởi động)")
    parser.add_argument("--labels-dir", required=True)
    parser.add_argument("--day", default="friday")
    parser.add_argument("--split", choices=["random", "time"], default="random")
    parser.add_argument("--manifest", help="mặc định data/work/cic/<day>_manifest.json")
    args = parser.parse_args(argv)

    data = load_day(args.labels_dir, args.day)
    X = feature_matrix(data)
    keep = X.notna().all(axis=1)
    logger.info("Bỏ %d dòng có Infinity/NaN", int((~keep).sum()))
    data, X = data[keep], X[keep]
    y = data["label"]
    logger.info("Số dòng theo lớp:\n%s", y.value_counts().to_string())

    if args.split == "random":
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    else:
        sets = assign_sets(data, args.manifest or f"data/work/cic/{args.day}_manifest.json")
        dev = sets == "dev"
        logger.info("Dòng theo tập: %s (chỉ dùng dev; test để dành cho lần thi)", sets.value_counts().to_dict())
        X, y, groups = X[dev], y[dev], (data.loc[dev, "ts"] // BLOCK_SECONDS)
        splitter = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=42)
        train_idx, val_idx = next(splitter.split(X, y, groups))
        X_train, X_val, y_train, y_val = X.iloc[train_idx], X.iloc[val_idx], y.iloc[train_idx], y.iloc[val_idx]
        logger.info("Validation theo lớp:\n%s", y_val.value_counts().to_string())

    model = RandomForestClassifier(n_estimators=100, max_depth=20, class_weight="balanced",
                                   n_jobs=-1, random_state=42)
    model.fit(X_train, y_train)
    report(y_train, model.predict(X_train), "Train (sách giáo khoa)")
    report(y_val, model.predict(X_val), f"Validation (đề thi thử, chia {args.split})")

    importance = pd.Series(model.feature_importances_, index=X.columns).sort_values(ascending=False)
    logger.info("15 đặc trưng quan trọng nhất:\n%s", importance.head(15).round(4).to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())