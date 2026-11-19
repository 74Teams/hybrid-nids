"""
Đặc trưng AI của một flow (PLAN-009 mục 6.7).

`extract_features` là hàm duy nhất tính đặc trưng: cả `tools/ai/build_dataset.py` (lúc học) lẫn
`AITrafficWorker` (lúc chạy) cùng gọi, để hai bên không lệch nhau. Đổi danh sách hay cách tính thì
phải dựng lại dataset và huấn luyện lại; mô hình cũ sẽ bị từ chối vì `feature_names` không khớp.
"""
import math
from typing import Dict, List, Optional

from nids.ai.context import SHORT_CONTEXT_FEATURE_NAMES
from nids.engine.flow import Flow

PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17, "ICMP": 1}

# Cột ngữ cảnh mà mô hình dùng (PLAN-011, lần 18). `FlowContext` vẫn tính đủ mọi cột, nhưng hai cột đếm 60 giây theo
# IP nguồn (`src_flows_60s`, `src_dst_ports_60s`) bị bỏ: chúng chỉ đầy dần sau khoảng 20 giây kể từ lúc đợt quét bắt
# đầu, nên mô hình học "chưa đầy nghĩa là bình thường" và bỏ lọt 20 giây đầu của mỗi đợt quét. Cột cửa sổ 5 giây
# (SHORT_CONTEXT_FEATURE_NAMES) đo tốc độ nên không có vùng mù đó.
MODEL_CONTEXT_FEATURES: List[str] = ["src_dst_hosts_60s", "src_short_ratio_60s", "dst_flows_60s",
                                     *SHORT_CONTEXT_FEATURE_NAMES]

# Thứ tự cột cố định, được lưu kèm mô hình. Không có IP và giờ tuyệt đối (tránh học thuộc dataset).
FEATURE_NAMES: List[str] = [
    "protocol", "dst_port", "flow_duration",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "fwd_len_min", "fwd_len_max", "fwd_len_mean", "fwd_len_std",
    "bwd_len_min", "bwd_len_max", "bwd_len_mean", "bwd_len_std",
    "fwd_payload_bytes", "bwd_payload_bytes",
    "flow_iat_mean", "flow_iat_std", "flow_iat_min", "flow_iat_max",
    "fwd_iat_mean", "bwd_iat_mean",
    "flow_packets_per_s", "flow_bytes_per_s", "down_up_ratio",
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count", "urg_count",
    # Nhìn nhiều flow của cùng IP (nids/ai/context.py)
    *MODEL_CONTEXT_FEATURES,
]


def _mean_std(total: float, square: float, count: int):
    if count <= 0:
        return 0.0, 0.0
    mean = total / count
    return mean, math.sqrt(max(0.0, square / count - mean * mean))


def extract_features(flow: Flow, context: Optional[Dict[str, float]] = None) -> Dict[str, float]:
    """Flow → dict {tên đặc trưng: giá trị}. Không bao giờ trả về inf hay NaN.

    `context` là kết quả của `FlowContext.update(flow)`; không có thì các cột ngữ cảnh bằng 0.
    """
    context = context or {}
    duration = flow.duration
    packets = flow.fwd_packets + flow.bwd_packets
    total_bytes = flow.fwd_bytes + flow.bwd_bytes
    fwd_mean, fwd_std = _mean_std(flow.fwd_bytes, flow.fwd_len_sq, flow.fwd_packets)
    bwd_mean, bwd_std = _mean_std(flow.bwd_bytes, flow.bwd_len_sq, flow.bwd_packets)
    iat_mean, iat_std = _mean_std(flow.iat_sum, flow.iat_sq, packets - 1)
    return {
        "protocol": PROTOCOL_NUMBERS.get(flow.protocol, 0),
        "dst_port": flow.dst_port or 0,
        "flow_duration": duration,
        "fwd_packets": flow.fwd_packets,
        "bwd_packets": flow.bwd_packets,
        "fwd_bytes": flow.fwd_bytes,
        "bwd_bytes": flow.bwd_bytes,
        "fwd_len_min": flow.fwd_len_min,
        "fwd_len_max": flow.fwd_len_max,
        "fwd_len_mean": fwd_mean,
        "fwd_len_std": fwd_std,
        "bwd_len_min": flow.bwd_len_min,
        "bwd_len_max": flow.bwd_len_max,
        "bwd_len_mean": bwd_mean,
        "bwd_len_std": bwd_std,
        "fwd_payload_bytes": flow.fwd_payload_bytes,
        "bwd_payload_bytes": flow.bwd_payload_bytes,
        "flow_iat_mean": iat_mean,
        "flow_iat_std": iat_std,
        "flow_iat_min": flow.iat_min,
        "flow_iat_max": flow.iat_max,
        "fwd_iat_mean": flow.fwd_iat_sum / (flow.fwd_packets - 1) if flow.fwd_packets > 1 else 0.0,
        "bwd_iat_mean": flow.bwd_iat_sum / (flow.bwd_packets - 1) if flow.bwd_packets > 1 else 0.0,
        # flow 0 giây (một gói): tốc độ ghi 0 thay vì vô cực như CICFlowMeter
        "flow_packets_per_s": packets / duration if duration > 0 else 0.0,
        "flow_bytes_per_s": total_bytes / duration if duration > 0 else 0.0,
        "down_up_ratio": flow.bwd_packets / flow.fwd_packets if flow.fwd_packets else 0.0,
        "syn_count": flow.syn_count,
        "ack_count": flow.ack_count,
        "fin_count": flow.fin_count,
        "rst_count": flow.rst_count,
        "psh_count": flow.psh_count,
        "urg_count": flow.urg_count,
        **{name: float(context.get(name, 0.0)) for name in MODEL_CONTEXT_FEATURES},
    }
