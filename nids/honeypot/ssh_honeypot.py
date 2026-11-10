# Thư viện
import hashlib
import logging
import socket
import threading
import time
import uuid

import paramiko

from .fake_shell import FakeShell
from .settings import settings
from .store import log_event

logger = logging.getLogger("nids.honeypot")

SSH_BANNER = settings.ssh_banner

# HASSH đo được trong lab; HASSH theo thư viện nên công cụ khác dùng libssh cũng có thể trùng hydra
KNOWN_HASSH = {
    "015322ee8471fa8338c558a918183b11": "hydra/libssh",   # hydra 9.7, libssh 0.12.2
    "eeca2460550b9ded084ecf2f70a75356": "OpenSSH",        # OpenSSH 10.2 và 10.6
    "4c94058d5e9e31659879f79fd5b46084": "paramiko",       # paramiko 5.1.0
}


def fake_response(cmd):
    """Trả về (output, exit status) giả cho một lệnh trong một phiên shell giả mới."""
    return FakeShell().run(cmd)


def crlf(text):
    """Terminal PTY ở chế độ raw không tự đổi \\n thành \\r\\n."""
    return text.replace('\n', '\r\n').encode()


def load_host_key(path=None):
    """Đọc host key; nếu chưa có thì tự sinh (mỗi máy một key riêng, không commit)."""
    path = path or settings.host_key_path
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        paramiko.RSAKey.generate(2048).write_private_key_file(str(path))
        logger.info("Đã sinh SSH host key mới tại %s", path)
    return paramiko.RSAKey(filename=str(path))


def compute_hassh(kex, ciphers, macs, compression):
    """HASSH: MD5 của danh sách thuật toán client đề xuất, dùng làm định danh chứ không để bảo mật."""
    raw = ";".join(",".join(algos) for algos in (kex, ciphers, macs, compression))
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


def identify_client(hassh, banner):
    """Tên công cụ: ưu tiên HASSH đã biết, không có thì dùng banner (do client tự khai, có thể giả)."""
    return KNOWN_HASSH.get(hassh) or banner.removeprefix("SSH-2.0-")[:64] or "không rõ"


class BruteForceTracker:
    """Đếm lần đăng nhập theo key; hai lần cách nhau quá window giây thì tính là đợt mới."""

    def __init__(self, threshold, window):
        self.threshold = threshold
        self.window = window
        self.bursts = {}                           # key -> (số lần, thời điểm gần nhất)
        self.lock = threading.Lock()

    def hit(self, key, now=None):
        """Ghi một lần đăng nhập; chỉ trả về True đúng lần chạm ngưỡng, mỗi đợt một cảnh báo."""
        now = time.monotonic() if now is None else now
        with self.lock:
            # dọn đợt đã hết để attacker đổi IP liên tục không làm đầy bộ nhớ
            self.bursts = {k: v for k, v in self.bursts.items() if now - v[1] <= self.window}
            count = self.bursts.get(key, (0, now))[0] + 1
            self.bursts[key] = (count, now)
            return count == self.threshold


bruteforce = BruteForceTracker(settings.ssh_bruteforce_threshold, settings.ssh_bruteforce_window)


class ConnectionLimiter:
    """Giới hạn số kết nối SSH đồng thời, tổng và theo IP; giá trị 0 là tắt giới hạn đó."""

    LOG_INTERVAL = 10            # giây giữa hai dòng log từ chối của cùng một IP, để flood không làm đầy log

    def __init__(self, max_total, max_per_ip):
        self.max_total = max_total
        self.max_per_ip = max_per_ip
        self.total = 0
        self.per_ip = {}                           # ip -> số kết nối đang mở
        self.last_log = {}                         # ip -> lần log từ chối gần nhất
        self.lock = threading.Lock()

    def acquire(self, ip):
        with self.lock:
            if self.max_total and self.total >= self.max_total:
                return False
            if self.max_per_ip and self.per_ip.get(ip, 0) >= self.max_per_ip:
                return False
            self.total += 1
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            return True

    def release(self, ip):
        with self.lock:
            self.total = max(0, self.total - 1)
            left = self.per_ip.get(ip, 0) - 1
            if left > 0:
                self.per_ip[ip] = left
            else:
                self.per_ip.pop(ip, None)          # xoá khoá để dict không phình khi đổi IP liên tục

    def should_log_rejection(self, ip, now=None):
        """True nếu đã đủ LOG_INTERVAL kể từ lần log từ chối trước của ip này."""
        now = time.monotonic() if now is None else now
        with self.lock:
            self.last_log = {k: t for k, t in self.last_log.items() if now - t < self.LOG_INTERVAL}
            if ip in self.last_log:
                return False
            self.last_log[ip] = now
            return True


limiter = ConnectionLimiter(settings.ssh_max_connections, settings.ssh_max_connections_per_ip)


class HasshTransport(paramiko.Transport):
    """Transport ghi HASSH của client vào conn, nên mọi sự kiện của kết nối đều mang giá trị này."""

    def __init__(self, sock, conn):
        super().__init__(sock)
        self.conn = conn
        self.quiet_close = False

    def _log(self, level, msg, *args):
        # đóng kết nối đang bắt tay (hết thời gian, bị giới hạn) khiến thread paramiko in traceback "Bad file
        # descriptor"; chỉ hạ mức log của lần đóng chủ động này, lỗi thật lúc đang chạy vẫn giữ nguyên
        if self.quiet_close and level >= logging.ERROR:
            level = logging.DEBUG
        super()._log(level, msg, *args)

    def _really_parse_kex_init(self, m, ignore_first_byte=False):
        # tính ở đây vì _parse_kex_init sẽ xoá ext-info-* và kex-strict-* khỏi danh sách kex
        parsed = super()._really_parse_kex_init(m, ignore_first_byte)
        if "hassh" not in self.conn:               # rekey không đổi fingerprint của kết nối
            self.conn["hassh"] = compute_hassh(parsed["kex_algo_list"],
                                               parsed["client_encrypt_algo_list"],
                                               parsed["client_mac_algo_list"],
                                               parsed["client_compress_algo_list"])
            self.conn["client_tool"] = identify_client(self.conn["hassh"], self.remote_version)
            logger.info("HASSH của %s: %s (%s)", self.conn["src_ip"], self.conn["hassh"], self.conn["client_tool"])
        return parsed


class SessionLimit(Exception):
    """Phiên shell vượt giới hạn tài nguyên (im lặng quá lâu hoặc sống quá lâu)."""


# emulated shell
def emulated_shell(channel, conn, shell=None, idle_timeout=None, session_max_seconds=None,
                   max_command_bytes=None):
    shell = shell or FakeShell()
    idle_timeout = settings.ssh_idle_timeout if idle_timeout is None else idle_timeout
    session_max_seconds = settings.ssh_session_max_seconds if session_max_seconds is None else session_max_seconds
    max_command_bytes = settings.ssh_max_command_bytes if max_command_bytes is None else max_command_bytes
    deadline = time.monotonic() + session_max_seconds if session_max_seconds else None

    def recv():
        """Đọc 1 byte; ném SessionLimit khi im quá idle_timeout hoặc quá tổng thời gian phiên."""
        wait = idle_timeout or None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SessionLimit("quá thời gian tối đa của phiên")
            wait = min(wait, remaining) if wait else remaining
        if hasattr(channel, "settimeout"):
            channel.settimeout(wait)
        try:
            return channel.recv(1)
        except socket.timeout:
            raise SessionLimit("im lặng quá thời gian cho phép") from None

    try:
        _shell_loop(channel, conn, shell, recv, max_command_bytes)
    except SessionLimit as limit:
        logger.info("Đóng phiên SSH của %s: %s", conn["src_ip"], limit)
        try:
            channel.send(b'\r\nConnection timed out\r\n')
        except Exception:
            pass
    channel.close()


def _shell_loop(channel, conn, shell, recv, max_command_bytes):
    channel.send(shell.prompt().encode())
    command = b''
    while True:
        char = recv()
        if not char:                               # client ngắt kết nối
            break

        if char in (b'\x7f', b'\x08'):             # backspace: xoá trọn một ký tự UTF-8 (bộ gõ tiếng Việt gửi ký tự nhiều byte rồi backspace)
            if command:
                end = len(command) - 1
                while end > 0 and 0x80 <= command[end] < 0xC0:   # lùi qua các byte nối tiếp
                    end -= 1
                command = command[:end]
                channel.send(b'\b \b')
            continue

        if char == b'\x03':                        # Ctrl+C
            channel.send(b'^C\r\n' + shell.prompt().encode())
            command = b''
            continue

        if char == b'\x04':                        # Ctrl+D
            if not command:
                channel.send(b'logout\r\n')
                break
            continue

        if char == b'\x1b':                        # chuỗi escape (mũi tên, Delete, Home...)
            nxt = recv()
            if nxt == b'[':
                while True:
                    b = recv()
                    if not b or b'@' <= b <= b'~':
                        break
            continue

        if char == b'\t' or (char[0] < 0x20 and char != b'\r'):   # Tab và ký tự điều khiển khác
            continue

        channel.send(char)                         # echo
        if char != b'\r':
            command += char
            if max_command_bytes and len(command) > max_command_bytes:
                raise SessionLimit(f"dòng lệnh dài quá {max_command_bytes} byte")
            continue

        cmd = command.strip().decode(errors='replace')
        command = b''
        if cmd:
            logger.info('Lệnh "%s" từ %s', cmd, conn["src_ip"])
            log_event('ssh', 'ssh.command', command=cmd, **conn)

        if cmd == 'exit':
            channel.send(b'\r\nlogout\r\n')
            break
        response, _ = shell.run(cmd)

        channel.send(b'\r\n')
        if response:
            channel.send(crlf(response) + b'\r\n')
        channel.send(shell.prompt().encode())


# ssh server + socket
class Server(paramiko.ServerInterface):
    def __init__(self, conn, input_username=None, input_password=None):
        self.event = threading.Event()
        self.conn = conn
        self.input_username = input_username
        self.input_password = input_password
        self.exec_command = None
        self.username = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        logger.info("Đăng nhập SSH từ %s: %s / %s", self.conn["src_ip"], username, password)
        log_event('ssh', 'ssh.auth.attempt', username=username, password=password, **self.conn)
        # theo cả HASSH: hydra mở kết nối mới cho mỗi mật khẩu, và một IP có thể chạy nhiều công cụ
        if bruteforce.hit((self.conn["src_ip"], self.conn.get("hassh"))):
            logger.warning("SSH brute force từ %s bằng %s", self.conn["src_ip"], self.conn.get("client_tool"))
            log_event('ssh', 'ssh.bruteforce', command=f"từ {bruteforce.threshold} lần đăng nhập", **self.conn)
        if self.input_username is not None and self.input_password is not None:
            if username != self.input_username or password != self.input_password:
                return paramiko.AUTH_FAILED
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        if isinstance(command, bytes):
            command = command.decode(errors='replace')
        logger.info('Lệnh exec "%s" từ %s', command, self.conn["src_ip"])
        log_event('ssh', 'ssh.exec', command=command, **self.conn)
        # chỉ ghi nhận ở đây: gửi output và đóng channel trước khi paramiko trả lời
        # request thì client nhận "Channel closed"; client_handle sẽ trả lời sau
        self.exec_command = command
        self.event.set()
        return True


def client_handle(client, addr, username, password, host_key, handshake_timeout=None,
                  auth_timeout=None, idle_timeout=None, session_max_seconds=None, max_command_bytes=None):
    """Xử lý một kết nối SSH; các giới hạn không truyền thì lấy từ settings (0 = không giới hạn)."""
    handshake_timeout = settings.ssh_handshake_timeout if handshake_timeout is None else handshake_timeout
    auth_timeout = settings.ssh_auth_timeout if auth_timeout is None else auth_timeout
    local_ip, local_port = client.getsockname()[:2]
    conn = {"src_ip": addr[0], "src_port": addr[1], "dst_ip": local_ip, "dst_port": local_port,
            "session_id": uuid.uuid4().hex}
    logger.info("%s kết nối tới SSH honeypot", addr[0])
    transport = None

    try:
        transport = HasshTransport(client, conn)
        transport.local_version = SSH_BANNER
        server = Server(conn, input_username=username, input_password=password)

        transport.add_server_key(host_key)
        # truyền event để start_server không chặn: client im lặng sau khi nối thì bị đóng sau handshake_timeout
        negotiated = threading.Event()
        transport.start_server(event=negotiated, server=server)
        if not negotiated.wait(handshake_timeout or None) or not transport.is_active():
            logger.info("Đóng kết nối SSH của %s: không hoàn tất bắt tay trong %ss", addr[0], handshake_timeout)
            return

        channel = transport.accept(auth_timeout or None)
        if channel is None:
            logger.debug("Không có channel nào được mở")
            return

        # chờ client yêu cầu shell hoặc exec
        if not server.event.wait(10):
            return

        shell = FakeShell(server.username or 'corpuser1',
                          on_event=lambda kind, detail: log_event('ssh', kind, command=detail, **conn))

        if server.exec_command is not None:
            response, status = shell.run(server.exec_command)
            if response:
                channel.send(response.encode() + b'\n')
            channel.send_exit_status(status)
            channel.close()
            transport.join(5)                      # chờ client nhận exit status và tự ngắt
            return

        standard_banner = settings.ssh_motd + "\r\n\r\n"
        channel.send(standard_banner.encode())
        emulated_shell(channel, conn, shell, idle_timeout=idle_timeout,
                       session_max_seconds=session_max_seconds, max_command_bytes=max_command_bytes)

    except Exception as e:
        logger.warning("Lỗi phiên SSH: %s", e)
    finally:
        if transport is not None:
            try:
                transport.quiet_close = True       # lỗi socket do chính ta đóng không phải lỗi đáng báo
                transport.close()
            except Exception:
                pass
        client.close()


def accept_connection(client, addr, username, password, host_key, conn_limiter=None, handler=None):
    """Nhận một kết nối: vượt giới hạn thì đóng ngay, ngược lại chạy client_handle ở thread riêng.

    Trả về True nếu đã giao cho thread. Không bao giờ ném lỗi ra ngoài để vòng accept không sập.
    """
    conn_limiter = conn_limiter or limiter
    handler = handler or client_handle
    ip = addr[0]
    if not conn_limiter.acquire(ip):
        if conn_limiter.should_log_rejection(ip):
            logger.warning("Từ chối kết nối SSH từ %s: vượt giới hạn kết nối đồng thời", ip)
        client.close()
        return False

    def run():
        try:
            handler(client, addr, username, password, host_key)
        except Exception as error:                 # lỗi một phiên không được kéo theo sensor
            logger.error("Lỗi không mong đợi ở phiên SSH từ %s: %s", ip, error)
        finally:
            conn_limiter.release(ip)

    try:
        threading.Thread(target=run, daemon=True).start()
    except Exception as error:                     # ví dụ cạn thread: trả lại chỗ, honeypot vẫn chạy
        conn_limiter.release(ip)
        client.close()
        logger.error("Không tạo được thread cho kết nối SSH từ %s: %s", ip, error)
        return False
    return True


# Provision SSH-based Honeypot
def honeypot(address, port, username, password):
    host_key = load_host_key()

    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)
    socks.settimeout(1.0)          # để vòng lặp kiểm tra Ctrl+C mỗi giây
    logger.info("SSH honeypot đang lắng nghe tại %s:%d", address, port)

    try:
        while True:
            try:
                client, addr = socks.accept()
            except socket.timeout:
                continue
            except OSError as error:
                logger.error("Lỗi socket: %s", error)
                break
            accept_connection(client, addr, username, password, host_key)
    finally:
        socks.close()
