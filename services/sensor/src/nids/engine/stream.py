"""
Tái hợp luồng TCP: ghép payload chiều client → server theo sequence number.

So khớp từng gói vẫn chạy như cũ; module này chỉ dựng thêm một gói ảo chứa dữ liệu đã ghép
khi có từ hai segment trở lên, để bắt chuỗi tấn công bị chia qua nhiều gói.
Chỉ ghép `depth` byte đầu của mỗi stream (giống stream.reassembly.depth của Suricata): buffer
luôn bắt đầu từ đầu stream hoặc đầu HTTP request nên offset/depth của rule vẫn đúng nghĩa.

Quét lại toàn bộ buffer ở mọi segment thì chi phí tăng theo bậc hai (upload lớn làm engine chậm
hàng chục lần), nên buffer lớn chỉ được quét khi gấp đôi lần trước hoặc ở các mốc bắt buộc.
"""
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, Optional, Set, Tuple

from nids.engine.decoder import HTTP_PORTS
from nids.engine.flow import FlowKey, SWEEP_INTERVAL, flow_key
from nids.engine.http_parser import HTTPParser
from nids.engine.packet import DecodedPacket
from nids.engine.rule import SnortRule

SEQ_SPACE = 1 << 32

# Buffer không quá ngần này byte thì quét ở mọi segment: chuỗi chia gói ngắn được phát hiện ngay
SCAN_EVERY_SEGMENT_BYTES = 4096

# Giá trị của _Stream.message_end khi buffer không phải HTTP request
NOT_HTTP = -1


def _seq_diff(a: int, b: int) -> int:
    """Hiệu a - b theo modulo 2^32, vì sequence number quay vòng về 0 sau 4 GiB."""
    return (a - b + SEQ_SPACE // 2) % SEQ_SPACE - SEQ_SPACE // 2


@dataclass
class StreamView:
    """Gói ảo chứa dữ liệu đã ghép, cùng tập SID đã bắn trên message hiện tại (để không báo trùng)."""
    packet: DecodedPacket
    fired: Set[int]


@dataclass
class _Stream:
    """Trạng thái ghép của một kết nối; `client` là đầu mút được ghép dữ liệu."""
    client: Tuple[str, int]
    next_seq: Optional[int] = None
    data: bytearray = field(default_factory=bytearray)
    segments: int = 0                                    # Số đoạn đang nằm trong `data`
    scanned: int = 0                                     # Số byte của `data` đã được so khớp
    message_end: Optional[int] = None                    # Vị trí kết thúc HTTP request đầu buffer
    pending: Dict[int, bytes] = field(default_factory=dict)  # Đoạn đến trước, chờ lấp khoảng trống
    fired: Set[int] = field(default_factory=set)
    exhausted: bool = False                              # Đã vượt depth, không ghép nữa
    last_seen: float = 0.0

    @property
    def size(self) -> int:
        return len(self.data) + sum(len(p) for p in self.pending.values())


class StreamReassembler:
    """Bảng stream đang ghép. Chỉ một thread được gọi vào đối tượng này (worker thread của engine)."""

    def __init__(self, depth: int = 65536, max_total_bytes: int = 67108864, max_streams: int = 50000,
                 idle_timeout: float = 30.0, max_pending_segments: int = 32):
        self.depth = depth
        self.max_total_bytes = max_total_bytes
        self.max_streams = max_streams
        self.idle_timeout = idle_timeout
        self.max_pending_segments = max_pending_segments
        # Sắp theo thời điểm cập nhật gần nhất: stream lâu nhất không có gói nằm đầu bảng
        self._streams: "OrderedDict[FlowKey, _Stream]" = OrderedDict()
        self._total_bytes = 0
        self._last_sweep: Optional[float] = None

    def __len__(self) -> int:
        return len(self._streams)

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    def feed(self, packet: DecodedPacket, matched: Iterable[SnortRule] = ()) -> Optional[StreamView]:
        """Nhận một gói đã so khớp xong; trả về gói ảo nếu có dữ liệu ghép mới cần so khớp lại.

        `matched` là các rule vừa khớp gói này, để lượt ghép không báo lại cùng SID.
        """
        if packet.protocol != "TCP" or packet.tcp_seq is None:
            return None
        now = packet.timestamp
        if self._last_sweep is None or now - self._last_sweep >= SWEEP_INTERVAL:
            self.expire(now)

        flags = packet.tcp_flags
        key = flow_key(packet)
        client_side = (packet.src_ip, packet.src_port or 0)

        if flags.get("SYN"):
            if not flags.get("ACK"):
                self._drop(key)
                self._open(key, client_side, now).next_seq = (packet.tcp_seq + 1) % SEQ_SPACE
            return None

        stream = self._streams.get(key)
        if stream is None:
            # Bắt giữa chừng, không thấy SYN: bên có cổng đích nhỏ hơn thường là client
            if not packet.raw_payload or (packet.dst_port or 0) >= (packet.src_port or 0):
                return None
            stream = self._open(key, client_side, now)

        closing = bool(flags.get("FIN") or flags.get("RST"))
        view = None
        if stream.client == client_side:
            stream.fired.update(rule.sid for rule in matched)
            stream.last_seen = now
            self._streams.move_to_end(key)
            before = stream.size
            view = self._ingest(stream, packet, closing)
            self._total_bytes += stream.size - before
        if closing:
            self._drop(key)
        elif self._total_bytes > self.max_total_bytes:
            self._evict(self.max_total_bytes)
        return view

    def expire(self, now: float) -> None:
        """Xoá stream không có gói trong `idle_timeout` giây tính đến `now`."""
        self._last_sweep = now
        for key in [k for k, s in self._streams.items() if now - s.last_seen >= self.idle_timeout]:
            self._drop(key)

    def _open(self, key: FlowKey, client: Tuple[str, int], now: float) -> _Stream:
        if len(self._streams) >= self.max_streams:
            self._drop(next(iter(self._streams)))
        stream = _Stream(client=client, last_seen=now)
        self._streams[key] = stream
        return stream

    def _drop(self, key: FlowKey) -> None:
        stream = self._streams.pop(key, None)
        if stream is not None:
            self._total_bytes -= stream.size

    def _evict(self, limit: int) -> None:
        while self._total_bytes > limit and self._streams:
            self._drop(next(iter(self._streams)))

    def _ingest(self, stream: _Stream, packet: DecodedPacket, closing: bool) -> Optional[StreamView]:
        """Đưa payload của gói vào buffer; trả về gói ảo nếu đến lúc so khớp lại dữ liệu đã ghép."""
        if stream.exhausted:
            return None
        accepted = bool(packet.raw_payload) and self._accept(stream, packet)
        return self._scan(stream, packet, closing) if accepted or closing else None

    def _accept(self, stream: _Stream, packet: DecodedPacket) -> bool:
        """Sắp payload vào đúng vị trí; True nếu buffer vừa có thêm dữ liệu liền mạch."""
        payload = packet.raw_payload
        if stream.next_seq is None:
            stream.next_seq = packet.tcp_seq

        gap = _seq_diff(packet.tcp_seq, stream.next_seq)
        if gap > 0:
            stream.pending[packet.tcp_seq] = payload
            if len(stream.pending) > self.max_pending_segments:
                self._resync(stream)
            return False
        payload = payload[-gap:]  # Gửi lại: dữ liệu đến trước được giữ, chỉ lấy phần còn mới
        if not payload:
            return False
        self._append(stream, payload)
        self._drain_pending(stream)
        return True

    def _append(self, stream: _Stream, payload: bytes) -> None:
        if len(stream.data) + len(payload) > self.depth:
            stream.exhausted = True  # Giữ `data` để _scan quét nốt rồi mới giải phóng
            return
        stream.data += payload
        stream.segments += 1
        stream.next_seq = (stream.next_seq + len(payload)) % SEQ_SPACE

    def _drain_pending(self, stream: _Stream) -> None:
        """Nối các đoạn đang chờ mà khoảng trống vừa được lấp."""
        while stream.pending and not stream.exhausted:
            seq = min(stream.pending, key=lambda s: _seq_diff(s, stream.next_seq))
            gap = _seq_diff(seq, stream.next_seq)
            if gap > 0:
                return
            payload = stream.pending.pop(seq)[-gap:]
            if payload:
                self._append(stream, payload)

    def _resync(self, stream: _Stream) -> None:
        """Khoảng trống không được lấp (mất gói): bỏ dữ liệu cũ, ghép lại từ đoạn đến muộn nhất."""
        latest = max(stream.pending, key=lambda seq: _seq_diff(seq, stream.next_seq))
        payload = stream.pending[latest]
        stream.data.clear()
        stream.pending.clear()
        stream.segments = 0
        stream.scanned = 0
        stream.message_end = None
        stream.fired = set()
        stream.next_seq = latest
        self._append(stream, payload)

    def _scan(self, stream: _Stream, packet: DecodedPacket, closing: bool) -> Optional[StreamView]:
        """Quyết định có so khớp lại buffer không, rồi cắt request đã đủ và giải phóng stream đã vượt depth."""
        end = self._message_end(stream, packet)
        complete = end is not None and end != NOT_HTTP and len(stream.data) >= end

        view = None
        if stream.segments < 2:
            stream.scanned = len(stream.data)  # Gói đơn lẻ đã được so khớp ở bước thường
        elif self._should_scan(stream, complete or closing):
            view = self._build_view(stream, packet)
            stream.scanned = len(stream.data)

        if complete:
            # Đủ một request: cắt khỏi buffer để request sau trên cùng kết nối được xét lại từ đầu
            del stream.data[:end]
            stream.segments = 1 if stream.data else 0
            stream.scanned = 0
            stream.message_end = None
            stream.fired = set()
        if stream.exhausted:
            stream.data.clear()
            stream.pending.clear()
            stream.segments = 0
        return view

    @staticmethod
    def _should_scan(stream: _Stream, forced: bool) -> bool:
        size = len(stream.data)
        if size <= stream.scanned:
            return False
        return forced or stream.exhausted or size <= SCAN_EVERY_SEGMENT_BYTES or size >= 2 * stream.scanned

    @staticmethod
    def _message_end(stream: _Stream, packet: DecodedPacket) -> Optional[int]:
        """Vị trí kết thúc HTTP request đầu buffer; None nếu chưa đủ header, NOT_HTTP nếu không phải HTTP.

        Chỉ parse header một lần cho mỗi request, không parse lại theo từng segment.
        """
        if stream.message_end is not None:
            return stream.message_end
        if packet.dst_port not in HTTP_PORTS:
            stream.message_end = NOT_HTTP
            return NOT_HTTP
        header_end = stream.data.find(b"\r\n\r\n")
        if header_end == -1:
            return None
        http_data = packet.http_data if stream.segments == 1 else HTTPParser.parse_payload(bytes(stream.data[:header_end]))
        if http_data is None:
            stream.message_end = NOT_HTTP
            return NOT_HTTP
        try:
            length = int(http_data.headers.get("content-length", 0))
        except ValueError:
            length = 0
        stream.message_end = header_end + 4 + max(length, 0)
        return stream.message_end

    @staticmethod
    def _build_view(stream: _Stream, packet: DecodedPacket) -> StreamView:
        data = bytes(stream.data)
        http_data = HTTPParser.parse_payload(data) if packet.dst_port in HTTP_PORTS else None
        ghost = replace(packet, raw_payload=data, raw_packet=b"", http_data=http_data, reassembled=True)
        return StreamView(ghost, stream.fired)
