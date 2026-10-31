"""
Shell giả cho SSH honeypot: filesystem trong RAM, trạng thái theo phiên (user, cwd).

Không bao giờ thực thi input của attacker: không subprocess/os.system/eval, không đọc
ghi file thật, không mở kết nối mạng. Đường dẫn chỉ xử lý bằng posixpath (thuần chuỗi).
"""
import posixpath
import shlex

from .settings import settings

HOSTNAME = settings.ssh_prompt.rstrip('$# ')
KERNEL = "6.8.0-45-generic"                         # khớp với ssh_motd
UNAME_V = "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024"

# Lệnh có output cố định, tra theo TÊN lệnh
STATIC = {
    'hostname': HOSTNAME,
    'uptime': ' 10:42:01 up 37 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01',
    'ps': '    PID TTY          TIME CMD\n   2210 pts/0    00:00:00 bash\n   2245 pts/0    00:00:00 ps',
    'w': (' 10:42:01 up 37 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n'
          'USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n'
          'corpuser pts/0    172.28.0.1       10:40    0.00s  0.02s  0.00s w'),
    'ifconfig': ('eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n'
                 '        inet 172.28.0.50  netmask 255.255.0.0  broadcast 172.28.255.255\n'
                 '        ether 02:42:ac:1c:00:32  txqueuelen 0  (Ethernet)\n\n'
                 'lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n'
                 '        inet 127.0.0.1  netmask 255.0.0.0'),
    'free': ('               total        used        free      shared  buff/cache   available\n'
             'Mem:         4013540     1123456     1890124        2340     1000960     2650084\n'
             'Swap:        2097148           0     2097148'),
    'df': ('Filesystem     1K-blocks    Used Available Use% Mounted on\n'
           '/dev/sda1       41152736 9876544  29162536  26% /\n'
           'tmpfs            2006768       0   2006768   0% /dev/shm'),
}

# Filesystem giả: path -> nội dung (None = thư mục)
FILES = {
    '/': None, '/etc': None, '/tmp': None, '/root': None, '/home': None,
    '/home/corpuser1': None, '/opt': None, '/opt/backup': None,
    '/etc/passwd': ('root:x:0:0:root:/root:/bin/bash\n'
                    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
                    'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n'
                    'sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n'
                    'corpuser1:x:1001:1001::/home/corpuser1:/bin/bash'),
    '/etc/shadow': 'root:$y$j9T$Qm0w7l6r1nB2$Xx9cV0aZ1Lq3mT8pR4sK7dF2gH5jW6eY0uI1oP3nM5b:19900:0:99999:7:::',
    '/etc/hostname': HOSTNAME,
    '/etc/os-release': ('PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
                        'VERSION="24.04.1 LTS (Noble Numbat)"\nID=ubuntu\nID_LIKE=debian'),
    '/home/corpuser1/jumpbox1.conf': 'HI, How are you today?',
    '/root/jumpbox1.conf': 'HI, How are you today?',
    '/opt/backup/db_backup.sh': "#!/bin/bash\nmysqldump -u backup -p'S3cr3t!' corp_db > /tmp/db.sql",  # mồi nhử
}


class FakeShell:
    def __init__(self, user='corpuser1', on_event=None):
        self.user = user
        self.home = '/root' if user == 'root' else '/home/corpuser1'
        self.cwd = self.home
        self.files = dict(FILES)          # bản sao riêng mỗi phiên (wget ghi vào đây)
        self.on_event = on_event or (lambda kind, detail: None)

    def prompt(self):
        where = '~' + self.cwd[len(self.home):] if self.cwd.startswith(self.home) else self.cwd
        return f"{self.user}@{HOSTNAME}:{where}{'#' if self.user == 'root' else '$'} "

    def path(self, p):
        """Đường dẫn tuyệt đối trong filesystem giả; chỉ xử lý chuỗi, không đụng ổ đĩa thật."""
        if p == '~' or p.startswith('~/'):
            p = self.home + p[1:]
        return posixpath.normpath(posixpath.join(self.cwd, p))

    def run(self, line):
        """Trả về (output, exit status); hỗ trợ nhiều lệnh nối bằng `;`."""
        outputs, status = [], 0
        for part in line.split(';'):
            out, status = self.run_one(part)
            if out:
                outputs.append(out)
        return ('\n'.join(outputs) or None), status

    def run_one(self, line):
        try:
            args = shlex.split(line)
        except ValueError:
            return 'bash: syntax error: unexpected end of file', 2
        if not args:
            return None, 0
        name, args = args[0], args[1:]
        handler = getattr(self, 'cmd_' + name, None)
        if handler:
            return handler(args)
        if name in STATIC:
            return STATIC[name], 0
        return f'bash: {name}: command not found', 127

    # Các lệnh cần trạng thái/tham số
    def cmd_whoami(self, a):
        return self.user, 0

    def cmd_pwd(self, a):
        return self.cwd, 0

    def cmd_id(self, a):
        uid = 0 if self.user == 'root' else 1001
        return f'uid={uid}({self.user}) gid={uid}({self.user}) groups={uid}({self.user})', 0

    def cmd_cd(self, a):
        p = self.path(a[0]) if a else self.home
        if self.files.get(p, '') is None:
            self.cwd = p
            return None, 0
        return f'bash: cd: {a[0]}: No such file or directory', 1

    def cmd_ls(self, a):
        flags = ''.join(x[1:] for x in a if x.startswith('-'))
        target = next((x for x in a if not x.startswith('-')), '.')
        p = self.path(target)
        if p not in self.files:
            return f"ls: cannot access '{target}': No such file or directory", 2
        if self.files[p] is not None:                     # ls một file
            return target, 0
        names = sorted(posixpath.basename(k) for k in self.files
                       if k != '/' and posixpath.dirname(k) == p)
        if 'a' in flags:
            names = ['.', '..'] + names
        return '  '.join(names) or None, 0

    def cmd_cat(self, a):
        out, status = [], 0
        for f in a:
            p = self.path(f)
            if p == '/etc/shadow' and self.user != 'root':
                out.append(f'cat: {f}: Permission denied')
                status = 1
            elif p not in self.files:
                out.append(f'cat: {f}: No such file or directory')
                status = 1
            elif self.files[p] is None:
                out.append(f'cat: {f}: Is a directory')
                status = 1
            elif self.files[p]:
                out.append(self.files[p])
        return '\n'.join(out) or None, status

    def cmd_uname(self, a):
        flags = ''.join(x[1:] for x in a if x.startswith('-'))
        if 'a' in flags:
            return f'Linux {HOSTNAME} {KERNEL} {UNAME_V} x86_64 x86_64 x86_64 GNU/Linux', 0
        parts = {'s': 'Linux', 'n': HOSTNAME, 'r': KERNEL, 'v': UNAME_V, 'm': 'x86_64', 'o': 'GNU/Linux'}
        return ' '.join(parts[c] for c in 'snrvmo' if c in flags) or 'Linux', 0

    def cmd_wget(self, a):
        url = next((x for x in a if not x.startswith('-')), None)
        if not url:
            return 'wget: missing URL', 1
        self.on_event('ssh.download', url)               # ghi lại URL payload, KHÔNG tải thật
        name = url.rstrip('/').split('/')[-1] or 'index.html'
        self.files[self.path(name)] = ''                  # tạo file rỗng để `ls` thấy
        return (f"--2024-10-29 10:42:01--  {url}\nConnecting... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n'{name}' saved"), 0

    def cmd_curl(self, a):
        url = next((x for x in a if not x.startswith('-')), None)
        if not url:
            return "curl: try 'curl --help' or 'curl --manual' for more information", 2
        self.on_event('ssh.download', url)
        return None, 0
