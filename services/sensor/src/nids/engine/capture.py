import logging
from typing import Callable, Optional
from scapy.all import conf, sniff
from scapy.packet import Packet, Padding, Raw

logger = logging.getLogger("nids.capture")

# Decoder chỉ dùng tới L4 (payload lấy nguyên byte sau header TCP/UDP/ICMP), nên Scapy không cần bóc DNS, TLS,
# NetBIOS... Giữ mọi lớp của ba module dưới (Ethernet/VLAN/ARP, IPv4/TCP/UDP/ICMP kể cả gói lỗi lồng trong ICMP,
# IPv6 và ICMPv6), phần sau L4 thành Raw. Đo trên chienbuoito.pcap (107.996 gói): decode nhanh hơn khoảng 23%,
# và `raw_packet = bytes(gói)` khớp byte gốc trên dây ở mọi gói (không lọc thì 117 gói bị Scapy dựng lại sai).
KEEP_LAYER_MODULES = ("scapy.layers.l2", "scapy.layers.inet", "scapy.layers.inet6")


def apply_layer_filter() -> None:
    """Chỉ cho Scapy bóc tới L4. Trạng thái toàn cục của Scapy, nên gọi ở `main()`, không gọi lúc import."""
    keep = [layer for layer in conf.layers if layer.__module__ in KEEP_LAYER_MODULES]
    conf.layers.filter(keep + [Raw, Padding])


def reset_layer_filter() -> None:
    """Bỏ lọc, Scapy bóc mọi tầng như mặc định (dùng trong test). Gọi khi chưa lọc cũng không lỗi."""
    if getattr(conf.layers, "filtered", False):
        conf.layers.unfilter()


class PacketCapture:
    """
    Module chuyên trách duy nhất: thu nhận gói tin thô từ card mạng hoặc file PCAP.

    Nguyên tắc thiết kế (không rớt gói):
    - Class này KHÔNG làm bất kỳ logic parse hay phân tích nào.
    - Khi nhận được gói tin từ card mạng, nó lập tức chuyển sang raw_callback.
    - raw_callback sẽ đẩy vào Queue, giúp vòng lặp bắt gói KHÔNG bao giờ bị block.

    Lợi ích:
    - Dễ thay thế thư viện bắt gói (Scapy -> pypcap) mà không ảnh hưởng code phía sau.
    - Luồng bắt gói tin chạy độc lập, nhẹ nhất có thể.
    """

    def __init__(self, raw_callback: Callable[[Packet], None], bpf_filter: str = "ip"):
        """
        Args:
            raw_callback: Hàm được gọi cho mỗi gói tin thô Scapy nhận được.
            bpf_filter:   Bộ lọc BPF (Berkeley Packet Filter), ví dụ: "ip", "tcp port 80".
        """
        self.raw_callback = raw_callback
        self.bpf_filter = bpf_filter

    def start_live(self, iface: Optional[str] = None) -> None:
        """
        Lắng nghe trực tiếp trên card mạng (chế độ Promiscuous).

        Args:
            iface: Tên card mạng (ví dụ: "Ethernet", "Wi-Fi").
                   None = tự động chọn card mặc định của hệ thống.
        """
        sniff(
            iface=iface,
            filter=self.bpf_filter,
            prn=self.raw_callback,
            store=False,  # Không lưu vào RAM, tiết kiệm bộ nhớ
        )

    def start_offline(self, pcap_path: str, stop_filter: Optional[Callable[[Packet], bool]] = None) -> None:
        """
        Đọc và phát lại toàn bộ gói tin từ file .pcap (chế độ offline/replay).

        Args:
            pcap_path:   Đường dẫn đến file .pcap cần phân tích.
            stop_filter: Gọi sau mỗi gói; trả về True thì dừng đọc (ví dụ khi worker đã dừng).
        """
        try:
            sniff(
                offline=pcap_path,
                filter=self.bpf_filter,
                prn=self.raw_callback,
                store=False,
                stop_filter=stop_filter,
            )
        except Exception as e:
            # Dự phòng: BPF filter cần tcpdump (Windows không có sẵn)
            # nên thử lại không dùng BPF filter
            if "tcpdump" in str(e).lower() or "not available" in str(e).lower():
                logger.warning("BPF filter không khả dụng, đọc PCAP không dùng filter")
                sniff(
                    offline=pcap_path,
                    prn=self.raw_callback,
                    store=False,
                    stop_filter=stop_filter,
                )
            else:
                raise
