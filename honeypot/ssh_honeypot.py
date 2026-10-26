# Thư viện
import logging
import socket
import threading

import paramiko

from .settings import settings
from .store import log_event

logger = logging.getLogger("nids.honeypot")

SSH_BANNER = settings.ssh_banner
PROMPT = settings.ssh_prompt.encode()


def load_host_key(path=None):
    """Đọc host key; nếu chưa có thì tự sinh (mỗi máy một key riêng, không commit)."""
    path = path or settings.host_key_path
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        paramiko.RSAKey.generate(2048).write_private_key_file(str(path))
        logger.info("Đã sinh SSH host key mới tại %s", path)
    return paramiko.RSAKey(filename=str(path))


# emulated shell
def emulated_shell(channel, conn):
    channel.send(PROMPT)
    command = b''
    while True:
        char = channel.recv(1)
        if not char:                               # client ngắt kết nối
            break

        if char in (b'\x7f', b'\x08'):             # backspace
            if command:
                command = command[:-1]
                channel.send(b'\b \b')
            continue

        if char == b'\x03':                        # Ctrl+C
            channel.send(b'^C\r\n' + PROMPT)
            command = b''
            continue

        if char == b'\x04':                        # Ctrl+D
            if not command:
                channel.send(b'logout\r\n')
                break
            continue

        if char == b'\x1b':                        # chuỗi escape (mũi tên, Delete, Home...)
            nxt = channel.recv(1)
            if nxt == b'[':
                while True:
                    b = channel.recv(1)
                    if not b or b'@' <= b <= b'~':
                        break
            continue

        if char == b'\t' or (char[0] < 0x20 and char != b'\r'):   # Tab và ký tự điều khiển khác
            continue

        channel.send(char)                         # echo
        if char != b'\r':
            command += char
            continue

        cmd = command.strip().decode(errors='replace')
        command = b''
        if cmd:
            logger.info('Lệnh "%s" từ %s', cmd, conn["src_ip"])
            log_event('ssh', 'ssh.command', command=cmd, **conn)

        if cmd == 'exit':
            channel.send(b'\r\nlogout\r\n')
            break
        elif cmd == 'pwd':
            response = '/usr/local'
        elif cmd == 'whoami':
            response = 'corpuser1'
        elif cmd == 'ls':
            response = 'jumpbox1.conf'
        elif cmd == 'cat jumpbox1.conf':
            response = 'HI, How are you today?'
        elif cmd == '':
            response = None
        else:
            response = f'bash: {cmd.split()[0]}: command not found'

        channel.send(b'\r\n')
        if response:
            channel.send(response.encode() + b'\r\n')
        channel.send(PROMPT)

    channel.close()


# ssh server + socket
class Server(paramiko.ServerInterface):
    def __init__(self, conn, input_username=None, input_password=None):
        self.event = threading.Event()
        self.conn = conn
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        logger.info("Đăng nhập SSH từ %s: %s / %s", self.conn["src_ip"], username, password)
        log_event('ssh', 'ssh.auth.attempt', username=username, password=password, **self.conn)
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED
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
        try:
            name = command.split()[0] if command.split() else ''
            channel.send(f'bash: {name}: command not found\r\n'.encode())
            channel.send_exit_status(127)
            channel.close()
        except Exception:
            pass
        return True


def client_handle(client, addr, username, password, host_key):
    local_ip, local_port = client.getsockname()[:2]
    conn = {"src_ip": addr[0], "src_port": addr[1], "dst_ip": local_ip, "dst_port": local_port}
    logger.info("%s kết nối tới SSH honeypot", addr[0])
    transport = None

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(conn, input_username=username, input_password=password)

        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            logger.debug("Không có channel nào được mở")
            return

        # chỉ vào shell khi client yêu cầu shell (exec đã được xử lý riêng)
        if not server.event.wait(10):
            return

        standard_banner = settings.ssh_motd + "\r\n\r\n"
        channel.send(standard_banner.encode())
        emulated_shell(channel, conn)

    except Exception as e:
        logger.warning("Lỗi phiên SSH: %s", e)
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        client.close()


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
            t = threading.Thread(target=client_handle,
                                 args=(client, addr, username, password, host_key),
                                 daemon=True)
            t.start()
    finally:
        socks.close()
