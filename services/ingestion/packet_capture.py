from typing import Callable, Optional
from scapy.all import sniff
from scapy.packet import Packet


class PacketCapture:
    """
    Module chuyen trach duy nhat: Thu nhan goi tin tho tu card mang hoac file PCAP.

    Nguyen tac thiet ke (Zero Packet Loss):
    - Class nay KHONG lam bat ky logic parse hay phan tich nao.
    - Khi nhan duoc goi tin tu card mang, no lap tuc chuyen sang raw_callback.
    - raw_callback se day vao Queue - giup vong lap bat goi KHONG bao gio bi block.

    Loi ich:
    - De dang thay the thu vien bat goi (Scapy -> pypcap) ma khong anh huong code phia sau.
    - Luong bat goi tin chay doc lap, nhe nhat co the.
    """

    def __init__(self, raw_callback: Callable[[Packet], None], bpf_filter: str = "ip"):
        """
        Args:
            raw_callback: Ham duoc goi cho moi goi tin tho Scapy nhan duoc.
            bpf_filter:   Bo loc BPF (Berkeley Packet Filter), vi du: "ip", "tcp port 80".
        """
        self.raw_callback = raw_callback
        self.bpf_filter = bpf_filter

    def start_live(self, iface: Optional[str] = None) -> None:
        """
        Lang nghe truc tiep tren card mang (che do Promiscuous).

        Args:
            iface: Ten card mang (vi du: "Ethernet", "Wi-Fi").
                   None = tu dong chon card mac dinh cua he thong.
        """
        sniff(
            iface=iface,
            filter=self.bpf_filter,
            prn=self.raw_callback,
            store=False,  # Khong luu vao RAM, tiet kiem bo nho
        )

    def start_offline(self, pcap_path: str) -> None:
        """
        Doc va phat lai toan bo goi tin tu file .pcap (che do offline/replay).

        Args:
            pcap_path: Duong dan den file .pcap can phan tich.
        """
        try:
            sniff(
                offline=pcap_path,
                filter=self.bpf_filter,
                prn=self.raw_callback,
                store=False,
            )
        except Exception as e:
            # Fallback: BPF filter can yeu cau tcpdump (khong co tren Windows mac dinh)
            # Thu lai khong dung BPF filter
            if "tcpdump" in str(e).lower() or "not available" in str(e).lower():
                print(f"[Warning] BPF filter khong kha dung, doc PCAP khong dung filter...")
                sniff(
                    offline=pcap_path,
                    prn=self.raw_callback,
                    store=False,
                )
            else:
                raise
