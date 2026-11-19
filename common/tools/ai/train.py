"""
Huấn luyện và chấm Random Forest cho AITrafficWorker (PLAN-011); chỉ dùng chunk dev.

Cách chấm: 4 lần chia cố định (`common/tools/ai/folds.csv`), mỗi flow validation được đoán đúng một lần bởi mô hình
chưa học khối của nó (out-of-fold), rồi gộp lại tính mọi chỉ số một lần.

    python -m tools.ai.train --make-folds                       # chạy một lần, tạo common/tools/ai/folds.csv
    python -m tools.ai.train --name lan-1 --no-save              # chấm một thí nghiệm, không ghi mô hình
    python -m tools.ai.train --features-dir data/work/ai/features --out data/models/flow_model.joblib
"""
import argparse
import hashlib
import logging
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Union

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedGroupKFold

from nids.ai.context import DEFAULT_MAX_PER_IP, DEFAULT_MAX_TRACKED, DEFAULT_SHORT_WINDOW, DEFAULT_WINDOW
from nids.ai.features import FEATURE_NAMES
from nids.logger import setup_logging

logger = logging.getLogger("nids.ai")

# WebAttack bị bỏ khỏi dữ liệu học: khác biệt nằm ở nội dung request, rule Snort lo (PLAN-011, quyết định B1)
SKIP_LABELS = {"UNLABELED", "EXCLUDED", "Heartbleed", "Infiltration", "WebAttack"}
# Lớp mà AI chịu trách nhiệm
AI_LABELS = ["BENIGN", "PortScan", "DoS", "DDoS", "Bot", "BruteForce"]
ATTACK_LABELS = [label for label in AI_LABELS if label != "BENIGN"]
BLOCK_SECONDS = 300
N_FOLDS = 4
TARGET_FPR = 0.01
VAL_BENIGN_PER_CHUNK = 5000      # mẫu BENIGN của validation: cố định, không đổi theo thí nghiệm
MIN_PAIR_FLOWS = 10              # nhóm (cặp IP, khối) ít hơn số flow này không tính vào tỷ lệ phát hiện
FOLDS_PATH = Path("common/tools/ai/folds.csv")
RF_PARAMS = dict(n_estimators=100, max_depth=20, min_samples_leaf=2, class_weight="balanced",
                 n_jobs=-1, random_state=42)
# Cột đếm ngữ cảnh (nids/ai/context.py, giai đoạn 3); `--scale-context` chỉ đụng các cột này
CONTEXT_COUNT_COLUMNS = ("src_flows_60s", "src_dst_ports_60s", "src_dst_hosts_60s", "dst_flows_60s",
                         "src_flows_5s", "src_dst_ports_5s", "src_dst_hosts_5s", "dst_flows_5s")
CONTEXT_OTHER_COLUMNS = ("src_short_ratio_60s", "dst_port_group", "src_port_diversity_5s")      # cột mới khác, chỉ để in hạng importance
INFO_COLUMNS = ["day", "chunk", "split", "first_seen", "src_ip", "dst_ip", "eval_label", "label_raw"]


# ---------------------------------------------------------------- đọc dữ liệu

def load_dev(features_dir: str, train_benign_per_chunk: int = VAL_BENIGN_PER_CHUNK) -> pd.DataFrame:
    """Đọc mọi chunk dev. Thêm cột `block`, `in_val`, `in_train`.

    Mỗi chunk lấy mẫu BENIGN hai lần (cùng `random_state=42`): mẫu validation cố định 5.000, mẫu train theo
    `train_benign_per_chunk`. Flow tấn công luôn thuộc cả hai. Hai mẫu giống nhau khi hai số này bằng nhau.
    """
    files = sorted(Path(features_dir).glob("*/*.csv.gz"))
    if not files:
        raise ValueError(f"Không có file .csv.gz nào trong {features_dir}")
    parts = []
    for path in files:
        frame = pd.read_csv(path)
        frame = frame[(frame["split"] == "dev") & ~frame["eval_label"].isin(SKIP_LABELS)]
        benign = frame[frame["eval_label"] == "BENIGN"]
        val_benign = benign.sample(VAL_BENIGN_PER_CHUNK, random_state=42) if len(benign) > VAL_BENIGN_PER_CHUNK else benign
        train_benign = benign.sample(train_benign_per_chunk, random_state=42) if len(benign) > train_benign_per_chunk else benign
        attack = frame[frame["eval_label"] != "BENIGN"]
        keep = pd.concat([benign.loc[benign.index.isin(val_benign.index) | benign.index.isin(train_benign.index)], attack])
        keep["in_val"] = keep.index.isin(val_benign.index) | (keep["eval_label"] != "BENIGN")
        keep["in_train"] = keep.index.isin(train_benign.index) | (keep["eval_label"] != "BENIGN")
        parts.append(keep)
    data = pd.concat(parts, ignore_index=True)
    missing = [name for name in FEATURE_NAMES if name not in data.columns]
    if missing:
        raise ValueError(f"Dataset thiếu cột: {', '.join(missing)}. Dựng lại bằng tools.ai.build_dataset")
    data["block"] = (data["first_seen"] // BLOCK_SECONDS).astype("int64")
    data["pair"] = np.where(data["src_ip"].astype(str) < data["dst_ip"].astype(str),
                            data["src_ip"].astype(str) + "|" + data["dst_ip"].astype(str),
                            data["dst_ip"].astype(str) + "|" + data["src_ip"].astype(str))
    logger.info("Đọc %d file, %d flow dev (validation %d, train %d)", len(files), len(data),
                int(data["in_val"].sum()), int(data["in_train"].sum()))
    return data


def dataset_version(features_dir: str) -> str:
    """Ngày + mã băm ngắn của danh sách file dataset: biết mô hình học từ dataset nào."""
    digest = hashlib.sha1()
    for path in sorted(Path(features_dir).glob("*/*.csv.gz")):
        digest.update(f"{path.parent.name}/{path.name}:{path.stat().st_size}".encode())
    return f"{date.today().isoformat()}-{digest.hexdigest()[:8]}"


# ---------------------------------------------------------------- chia cố định

def assign_folds(meta: pd.DataFrame, n_folds: int = N_FOLDS) -> pd.DataFrame:
    """Gán mỗi khối (day, block) vào một phần. `meta` có cột day, first_seen, eval_label. Trả về day, block, fold."""
    meta = meta.reset_index(drop=True)
    block = (meta["first_seen"] // BLOCK_SECONDS).astype("int64")
    groups = (meta["day"].astype(str) + "-" + block.astype(str)).to_numpy()
    fold = np.full(len(meta), -1, dtype=int)
    splitter = StratifiedGroupKFold(n_splits=n_folds, shuffle=True, random_state=42)
    for k, (_, val_idx) in enumerate(splitter.split(np.zeros(len(meta)), meta["eval_label"].to_numpy(), groups)):
        fold[val_idx] = k
    table = pd.DataFrame({"day": meta["day"].to_numpy(), "block": block.to_numpy(), "fold": fold})
    table = table.drop_duplicates().sort_values(["day", "block"]).reset_index(drop=True)
    return table


def make_folds(features_dir: str, path: Path = FOLDS_PATH) -> Path:
    """Tạo file chia cố định từ MỌI flow dev (trước khi lấy mẫu BENIGN). Từ chối ghi đè."""
    if path.exists():
        raise ValueError(f"{path} đã có. Xoá tay nếu thật sự muốn chia lại (mọi số cũ sẽ không so được nữa)")
    files = sorted(Path(features_dir).glob("*/*.csv.gz"))
    if not files:
        raise ValueError(f"Không có file .csv.gz nào trong {features_dir}")
    meta = []
    for file in files:
        frame = pd.read_csv(file, usecols=["day", "split", "first_seen", "eval_label"])
        meta.append(frame[(frame["split"] == "dev") & ~frame["eval_label"].isin(SKIP_LABELS)])
    table = assign_folds(pd.concat(meta, ignore_index=True))
    path.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(path, index=False)
    logger.info("Đã tạo %s: %d khối, mã %s", path, len(table), folds_version(path))
    return path


def folds_version(path: Path = FOLDS_PATH) -> str:
    return hashlib.sha1(Path(path).read_bytes()).hexdigest()[:8]


def attach_folds(data: pd.DataFrame, folds: pd.DataFrame) -> pd.DataFrame:
    """Gắn cột `fold` theo (day, block). Khối không có trong bảng thì báo lỗi."""
    merged = data.merge(folds, on=["day", "block"], how="left")
    missing = merged[merged["fold"].isna()][["day", "block"]].drop_duplicates()
    if len(missing):
        sample = ", ".join(f"{r.day}/{r.block}" for r in missing.head(5).itertuples())
        raise ValueError(f"{len(missing)} khối không có trong folds.csv (ví dụ {sample}). Dataset đã đổi sau khi chia?")
    merged["fold"] = merged["fold"].astype(int)
    return merged


# ---------------------------------------------------------------- ngưỡng

Thresholds = Union[float, Dict[str, float]]


def apply_threshold(proba: np.ndarray, classes: np.ndarray, threshold: Thresholds) -> np.ndarray:
    """Nhãn có xác suất cao nhất; nếu là tấn công nhưng xác suất < ngưỡng của lớp đó thì coi là BENIGN."""
    best = proba.argmax(axis=1)
    labels = np.asarray(classes)[best].astype(object)
    if isinstance(threshold, dict):
        limit = np.array([threshold.get(str(c), 0.5) for c in classes])[best]
    else:
        limit = threshold
    labels[(labels != "BENIGN") & (proba.max(axis=1) < limit)] = "BENIGN"
    return labels


def choose_thresholds(proba: np.ndarray, classes: np.ndarray, y: np.ndarray, target_fpr: float = TARGET_FPR) -> Dict[str, float]:
    """Ngưỡng nhỏ nhất cho từng lớp tấn công mà số BENIGN bị đoán nhầm sang lớp đó ≤ phần FPR được chia.

    FPR mục tiêu chia đều cho các lớp tấn công có trong mô hình; không ngưỡng nào đạt thì lấy 0,95.
    """
    classes = np.asarray(classes)
    attack = [str(c) for c in classes if c != "BENIGN"]
    benign = np.asarray(y) == "BENIGN"
    total = int(benign.sum())
    best = proba.argmax(axis=1)
    confidence = proba.max(axis=1)
    result = {}
    for label in attack:
        if total == 0:
            result[label] = 0.5
            continue
        wrong = benign & (best == int(np.where(classes == label)[0][0]))
        share = target_fpr / len(attack)
        result[label] = 0.95
        for threshold in np.arange(0.50, 0.951, 0.05):
            if (wrong & (confidence >= round(float(threshold), 2))).sum() / total <= share:
                result[label] = round(float(threshold), 2)
                break
    return result


# ---------------------------------------------------------------- học và dự đoán out-of-fold

def align_proba(proba: np.ndarray, model_classes: Sequence, classes: Sequence) -> np.ndarray:
    """Đặt cột xác suất của mô hình vào đúng vị trí trong danh sách lớp chung (lớp mô hình không có: 0)."""
    index = {str(c): i for i, c in enumerate(classes)}
    out = np.zeros((proba.shape[0], len(classes)))
    for j, label in enumerate(model_classes):
        out[:, index[str(label)]] = proba[:, j]
    return out


def out_of_fold(X: np.ndarray, y: np.ndarray, fold: np.ndarray, in_train: np.ndarray, in_val: np.ndarray,
                classes: np.ndarray, rf_params: dict, X_val: Optional[np.ndarray] = None,
                importances: Optional[list] = None) -> np.ndarray:
    """Với mỗi phần k: học trên các phần còn lại (đã lọc `in_train`), đoán xác suất cho phần k (`in_val`).

    Hàng không thuộc `in_val` có xác suất NaN. `X_val` (nếu có) thay X khi đoán, dùng cho `--scale-context`.
    """
    proba = np.full((len(y), len(classes)), np.nan)
    source = X if X_val is None else X_val
    for k in sorted(set(fold.tolist())):
        train = (fold != k) & in_train
        val = (fold == k) & in_val
        if not val.any():
            logger.warning("Phần %d không có flow validation", k)
            continue
        model = RandomForestClassifier(**rf_params).fit(X[train], y[train])
        proba[val] = align_proba(model.predict_proba(source[val]), model.classes_, classes)
        if importances is not None:
            importances.append(model.feature_importances_)
        logger.info("Phần %d: học %d flow, đoán %d flow", k, int(train.sum()), int(val.sum()))
    return proba


# ---------------------------------------------------------------- số đo

def fpr_of(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    benign = np.asarray(y_true) == "BENIGN"
    return float((np.asarray(y_pred)[benign] != "BENIGN").mean()) if benign.any() else 0.0


def pair_report(frame: pd.DataFrame, pred: np.ndarray, min_flows: int = MIN_PAIR_FLOWS) -> dict:
    """Số đo theo (ngày, cặp IP không phân chiều, khối 5 phút).

    Mỗi lớp tấn công: số nhóm có ≥ `min_flows` flow thuộc lớp, số nhóm bị phát hiện (có ≥ 1 flow đoán là tấn công),
    số nhóm nhỏ bị loại. Cặp báo nhầm: nhóm toàn BENIGN nhưng có flow bị đoán là tấn công.
    """
    df = pd.DataFrame({"day": frame["day"].to_numpy(), "pair": frame["pair"].to_numpy(),
                       "block": frame["block"].to_numpy(), "label": frame["eval_label"].to_numpy(),
                       "hit": np.asarray(pred) != "BENIGN"})
    keys = ["day", "pair", "block"]
    report = {"attack": {}}
    for label in ATTACK_LABELS:
        sub = df[df["label"] == label]
        if sub.empty:
            continue
        groups = sub.groupby(keys).agg(n=("hit", "size"), detected=("hit", "any"))
        big = groups[groups["n"] >= min_flows]
        report["attack"][label] = {"groups": len(big), "detected": int(big["detected"].sum()),
                                   "small": len(groups) - len(big)}
    df["is_attack"] = df["label"] != "BENIGN"
    groups = df.groupby(keys).agg(any_attack=("is_attack", "any"), any_hit=("hit", "any"))
    benign_groups = groups[~groups["any_attack"]]
    report["false_pairs"] = int(benign_groups["any_hit"].sum())
    report["benign_pairs"] = len(benign_groups)
    return report


def score(frame: pd.DataFrame, pred: np.ndarray) -> dict:
    """Mọi chỉ số trên bảng out-of-fold gộp."""
    y = frame["eval_label"].to_numpy()
    labels_all = sorted(set(y) | set(pred))
    labels_ai = [label for label in AI_LABELS if label in set(y) | set(pred)]
    detail = classification_report(y, pred, labels=labels_all, output_dict=True, zero_division=0)
    raw = frame["label_raw"].astype(str)
    non_hulk = (frame["eval_label"] == "DoS") & ~raw.str.contains("Hulk", case=False)
    result = {
        "labels_all": labels_all,
        "fpr": fpr_of(y, pred),
        "macro_f1_ai": float(f1_score(y, pred, labels=labels_ai, average="macro", zero_division=0)),
        "macro_f1_all": float(f1_score(y, pred, labels=labels_all, average="macro", zero_division=0)),
        "recall": {l: detail[l]["recall"] for l in labels_all if l in set(y)},
        "precision": {l: detail[l]["precision"] for l in labels_all},
        "dos_non_hulk": float((pred[non_hulk.to_numpy()] == "DoS").mean()) if non_hulk.any() else float("nan"),
        "pairs": pair_report(frame, pred),
    }
    by_raw = []
    for (label, tool), part in frame.assign(pred=pred).groupby(["eval_label", "label_raw"]):
        if label in ATTACK_LABELS or label == "WebAttack":
            by_raw.append((label, tool, len(part), float((part["pred"] == label).mean())))
    result["by_raw"] = by_raw
    return result


def log_score(title: str, frame: pd.DataFrame, pred: np.ndarray) -> dict:
    y = frame["eval_label"].to_numpy()
    result = score(frame, pred)
    labels = result["labels_all"]
    logger.info("=== %s ===\n%s", title, classification_report(y, pred, labels=labels, digits=3, zero_division=0))
    matrix = pd.DataFrame(confusion_matrix(y, pred, labels=labels),
                          index=[f"thật {l}" for l in labels], columns=[f"đoán {l}" for l in labels])
    logger.info("Ma trận nhầm lẫn:\n%s", matrix.to_string())
    logger.info("FPR: %.3f%%, macro F1 (6 lớp AI): %.3f, macro F1 (mọi lớp): %.3f",
                100 * result["fpr"], result["macro_f1_ai"], result["macro_f1_all"])
    lines = [f"  {label}: {item['detected']}/{item['groups']} nhóm bị phát hiện (bỏ {item['small']} nhóm dưới {MIN_PAIR_FLOWS} flow)"
             for label, item in result["pairs"]["attack"].items()]
    lines.append(f"  cặp báo nhầm: {result['pairs']['false_pairs']}/{result['pairs']['benign_pairs']} nhóm toàn BENIGN "
                 "(số tương đối, BENIGN đã lấy mẫu)")
    logger.info("Theo cặp IP trong khối 5 phút:\n%s", "\n".join(lines))
    logger.info("Recall theo công cụ (label_raw):\n%s", "\n".join(
        f"  {label:<10} {tool:<28} {n:>7} flow  recall {recall:.3f}" for label, tool, n, recall in result["by_raw"]))
    logger.info("Recall DoS không phải Hulk: %.3f", result["dos_non_hulk"])
    return result


def log_per_fold(frame: pd.DataFrame, pred: np.ndarray, fold: np.ndarray) -> None:
    """Số phụ theo từng phần chia: số flow mỗi lớp và recall (dấu - nghĩa là phần đó không có mẫu của lớp)."""
    y = frame["eval_label"].to_numpy()
    labels = sorted(set(y))
    counts, recalls = {}, {}
    for k in sorted(set(fold.tolist())):
        mask = fold == k
        counts[f"phần {k}"] = {l: int((y[mask] == l).sum()) for l in labels}
        recalls[f"phần {k}"] = {l: (f"{(pred[mask & (y == l)] == l).mean():.3f}" if (mask & (y == l)).any() else "-")
                                for l in labels}
    logger.info("Số flow validation mỗi lớp theo phần:\n%s", pd.DataFrame(counts).T.to_string())
    logger.info("Recall mỗi lớp theo phần (chỉ để tham khảo, số chính là bảng gộp):\n%s",
                pd.DataFrame(recalls).T.to_string())


def table_row(name: str, result: dict) -> str:
    recall = result["recall"]
    precision = result["precision"]

    def number(value) -> str:
        return "-" if value is None or value != value else f"{value:.3f}"

    return "| {} | {:.3f}% | {} | {} | {} | {} | {} | {} | {} | {} |".format(
        name, 100 * result["fpr"], number(recall.get("Bot")), number(recall.get("PortScan")), number(recall.get("DoS")),
        number(result["dos_non_hulk"]), number(recall.get("DDoS")), number(precision.get("WebAttack")),
        number(result["macro_f1_ai"]), number(result["macro_f1_all"]))


TABLE_HEADER = ("| Lần | FPR | Recall Bot | Recall PortScan | Recall DoS | Recall DoS (không Hulk) | Recall DDoS "
                "| Precision WebAttack | macro F1 (6 lớp AI) | macro F1 (mọi lớp) |\n"
                "|---|---|---|---|---|---|---|---|---|---|")


# ---------------------------------------------------------------- tham số dòng lệnh

def parse_rf_params(text: Optional[str]) -> dict:
    """`max_depth=15,n_estimators=200` → ghi đè RF_PARAMS. Giá trị `None` thành None; số thành int hoặc float."""
    params = dict(RF_PARAMS)
    if not text:
        return params
    for item in text.split(","):
        if "=" not in item:
            raise ValueError(f"--rf-params sai ở '{item}': cần dạng khoá=giá trị")
        key, value = (part.strip() for part in item.split("=", 1))
        if key not in RF_PARAMS:
            raise ValueError(f"--rf-params: khoá '{key}' không có trong {sorted(RF_PARAMS)}")
        if value == "None":
            params[key] = None
        else:
            try:
                params[key] = int(value)
            except ValueError:
                try:
                    params[key] = float(value)
                except ValueError:
                    params[key] = value
    return params


def parse_scale(text: Optional[str]) -> Optional[tuple]:
    if not text:
        return None
    if "=" not in text:
        raise ValueError("--scale-context cần dạng lớp=hệ số, ví dụ PortScan=0.1")
    label, factor = text.split("=", 1)
    return label.strip(), float(factor)


def scale_context(X: np.ndarray, feature_cols: List[str], eval_label: np.ndarray, spec: tuple) -> np.ndarray:
    """Nhân các cột đếm ngữ cảnh của flow thuộc lớp `spec[0]` với `spec[1]` (giá trị nhỏ nhất vẫn là 1)."""
    columns = [i for i, name in enumerate(feature_cols) if name in CONTEXT_COUNT_COLUMNS]
    if not columns:
        raise ValueError("--scale-context: dataset chưa có cột ngữ cảnh (làm sau giai đoạn 3)")
    label, factor = spec
    out = X.copy()
    rows = eval_label == label
    out[np.ix_(rows, columns)] = np.maximum(1.0, out[np.ix_(rows, columns)] * factor)
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Huấn luyện và chấm Random Forest cho AITrafficWorker")
    parser.add_argument("--features-dir", default="data/work/ai/features")
    parser.add_argument("--out", default="data/models/flow_model.joblib")
    parser.add_argument("--folds", default=str(FOLDS_PATH), help="file chia cố định")
    parser.add_argument("--make-folds", action="store_true", help="tạo file chia cố định rồi thoát")
    parser.add_argument("--name", default="thu-nghiem", help="tên thí nghiệm, in kèm một dòng bảng Markdown")
    parser.add_argument("--no-save", action="store_true", help="chỉ chấm, không học mô hình cuối và không ghi file")
    parser.add_argument("--benign-per-chunk", type=int, default=VAL_BENIGN_PER_CHUNK,
                        help="số BENIGN mỗi chunk cho phần train (validation luôn là 5000)")
    parser.add_argument("--rf-params", help="ghi đè RF_PARAMS, ví dụ max_depth=15,n_estimators=200")
    parser.add_argument("--target-fpr", type=float, default=TARGET_FPR)
    parser.add_argument("--drop-features", help="bỏ cột khi học, ví dụ dst_port (cần --no-save)")
    parser.add_argument("--train-drop-short-benign", type=float, default=0.0,
                        help="bỏ ngẫu nhiên tỷ lệ này của BENIGN có ≤ 2 gói, chỉ ở phần train (cần --no-save)")
    parser.add_argument("--holdout-raw-label", help="bỏ flow có label_raw chứa chuỗi này khỏi phần train (cần --no-save)")
    parser.add_argument("--scale-context", help="lớp=hệ số: nhân cột ngữ cảnh của flow validation lớp đó (cần --no-save)")
    parser.add_argument("--dump-errors", help="ghi flow validation bị đoán sai ra file CSV này")
    return parser


def run(args: argparse.Namespace) -> int:
    experiment = [args.drop_features, args.holdout_raw_label, args.scale_context,
                  args.train_drop_short_benign or None]
    if any(experiment) and not args.no_save:
        raise ValueError("--drop-features, --train-drop-short-benign, --holdout-raw-label, --scale-context "
                         "chỉ dùng để thí nghiệm: phải đi kèm --no-save")
    rf_params = parse_rf_params(args.rf_params)
    scale = parse_scale(args.scale_context)
    feature_cols = list(FEATURE_NAMES)
    if args.drop_features:
        dropped = [name.strip() for name in args.drop_features.split(",")]
        unknown = [name for name in dropped if name not in FEATURE_NAMES]
        if unknown:
            raise ValueError(f"--drop-features: không có cột {', '.join(unknown)}")
        feature_cols = [name for name in FEATURE_NAMES if name not in dropped]

    folds_path = Path(args.folds)
    if not folds_path.exists():
        raise ValueError(f"Chưa có {folds_path}. Chạy một lần: python -m tools.ai.train --make-folds")
    data = load_dev(args.features_dir, args.benign_per_chunk)
    data = attach_folds(data, pd.read_csv(folds_path))

    in_train = data["in_train"].to_numpy().copy()
    in_val = data["in_val"].to_numpy()
    rng = np.random.default_rng(42)
    if args.train_drop_short_benign:
        short = ((data["eval_label"] == "BENIGN") & (data["fwd_packets"] + data["bwd_packets"] <= 2)).to_numpy()
        in_train &= ~(short & (rng.random(len(data)) < args.train_drop_short_benign))
    if args.holdout_raw_label:
        in_train &= ~data["label_raw"].astype(str).str.contains(args.holdout_raw_label, case=False).to_numpy()

    classes = np.array(sorted(data["eval_label"].unique()))
    X = data[feature_cols].to_numpy(dtype="float64")
    y = data["eval_label"].to_numpy()
    fold = data["fold"].to_numpy()
    X_val = scale_context(X, feature_cols, y, scale) if scale else None
    logger.info("Flow dev mỗi lớp (validation):\n%s", data[in_val]["eval_label"].value_counts().to_string())

    importances: list = []
    proba = out_of_fold(X, y, fold, in_train, in_val, classes, rf_params, X_val, importances)
    mean_importance = pd.Series(np.mean(importances, axis=0), index=feature_cols).sort_values(ascending=False)
    logger.info("Độ quan trọng đặc trưng (trung bình 4 phần), 15 cột đầu:\n%s",
                mean_importance.head(15).round(4).to_string())
    context_rank = [(name, round(float(mean_importance[name]), 4), list(mean_importance.index).index(name) + 1)
                    for name in feature_cols if name in CONTEXT_COUNT_COLUMNS or name in CONTEXT_OTHER_COLUMNS]
    if context_rank:
        logger.info("Cột ngữ cảnh (tên, độ quan trọng, hạng trên %d cột): %s", len(feature_cols), context_rank)
    val = in_val
    val_frame = data[val].reset_index(drop=True)
    val_proba, val_y, val_fold = proba[val], y[val], fold[val]

    log_score("Validation gộp, ngưỡng 0.5", val_frame, apply_threshold(val_proba, classes, 0.5))
    thresholds = choose_thresholds(val_proba, classes, val_y, args.target_fpr)
    logger.info("Ngưỡng theo lớp (FPR mục tiêu %.3f%%): %s", 100 * args.target_fpr, thresholds)
    pred = apply_threshold(val_proba, classes, thresholds)
    result = log_score("Validation gộp, ngưỡng theo lớp", val_frame, pred)
    log_per_fold(val_frame, pred, val_fold)

    if args.dump_errors:
        wrong = val_frame.assign(pred=pred)[pred != val_y]
        Path(args.dump_errors).parent.mkdir(parents=True, exist_ok=True)
        wrong.to_csv(args.dump_errors, index=False)
        logger.info("Đã ghi %d flow đoán sai vào %s", len(wrong), args.dump_errors)

    logger.info("Dòng bảng báo cáo:\n%s\n%s", TABLE_HEADER, table_row(args.name, result))

    if args.no_save:
        logger.info("--no-save: không học mô hình cuối, không ghi file")
        return 0
    final = RandomForestClassifier(**rf_params).fit(X[in_train], y[in_train])
    bundle = {"rf": final, "feature_names": list(feature_cols), "labels": [str(c) for c in final.classes_],
              "thresholds": {"rf": max(thresholds.values()) if thresholds else 0.5, "per_class": thresholds},
              "version": dataset_version(args.features_dir), "folds_version": folds_version(folds_path),
              "sklearn_version": sklearn.__version__,
              # Tham số FlowContext lúc dựng đặc trưng: worker phải dùng đúng các giá trị này (PLAN-011 mục 6.3)
              "context": {"window": DEFAULT_WINDOW, "short_window": DEFAULT_SHORT_WINDOW,
                          "max_tracked": DEFAULT_MAX_TRACKED, "max_per_ip": DEFAULT_MAX_PER_IP}}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.out, compress=3)
    logger.info("Đã lưu %s (phiên bản %s, %.1f MB)", args.out, bundle["version"], Path(args.out).stat().st_size / 2**20)
    return 0


def main(argv=None) -> int:
    setup_logging("INFO")
    args = build_parser().parse_args(argv)
    try:
        if args.make_folds:
            make_folds(args.features_dir, Path(args.folds))
            return 0
        return run(args)
    except ValueError as error:
        logger.error("%s", error)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
