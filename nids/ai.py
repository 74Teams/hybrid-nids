from typing import Optional, Callable
from nids.engine.packet import DecodedPacket

class AITrafficWorker:
    """
    Worker AI phát hiện bất thường lưu lượng (Hiện đang ở chế độ tạm ngưng/chờ phát triển).
    """

    def __init__(self, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback

    def analyze_packet(self, packet: DecodedPacket) -> None:
        pass

