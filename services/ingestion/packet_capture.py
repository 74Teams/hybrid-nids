import logging
from typing import Callable, Optional
from scapy.all import sniff
from scapy.packet import Packet

logger = logging.getLogger("nids.capture")


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

    def start_offline(self, pcap_path: str) -> None:
        """
        Đọc và phát lại toàn bộ gói tin từ file .pcap (chế độ offline/replay).

        Args:
            pcap_path: Đường dẫn đến file .pcap cần phân tích.
        """
        try:
            sniff(
                offline=pcap_path,
                filter=self.bpf_filter,
                prn=self.raw_callback,
                store=False,
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
                )
            else:
                raise
