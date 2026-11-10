import logging
import re
import uuid

from flask import Flask, g, render_template, request
from waitress import serve

from .settings import settings
from .store import log_event

logger = logging.getLogger("nids.honeypot")

SQLI = re.compile(r"('|--|OR\s+\d|UNION|SELECT)", re.I)

SESSION_COOKIE = "wordpress_sess"
SESSION_ID = re.compile(r"[0-9a-f]{32}")


def web_honeypot(input_username=settings.http_username, input_password=settings.http_password):
    app = Flask(__name__)
    # lớp thứ hai sau max_request_body_size của waitress; không ghi sự kiện chứa body quá lớn
    app.config["MAX_CONTENT_LENGTH"] = settings.http_max_body_bytes or None

    @app.errorhandler(413)
    def too_large(_):
        logger.warning("Từ chối request quá lớn từ %s", request.remote_addr)
        return "Request Entity Too Large", 413

    @app.before_request
    def load_session():
        # cookie do attacker gửi: sai định dạng thì cấp id mới, tránh vượt cột session_id
        cookie = request.cookies.get(SESSION_COOKIE, '')
        g.new_session = not SESSION_ID.fullmatch(cookie)
        g.session_id = uuid.uuid4().hex if g.new_session else cookie
        # đọc body đúng một lần, trước mọi route: get_data(cache=True) để request.form trong login() vẫn parse được;
        # MAX_CONTENT_LENGTH chặn body quá lớn (kể cả chunked), khi đó sự kiện chỉ không có body
        try:
            g.body = request.get_data(cache=True).decode('utf-8', errors='replace') or None
        except Exception:
            g.body = None

    def request_fields():
        """Trường chung của mọi sự kiện HTTP; waitress đặt SERVER_NAME theo cấu hình server nên dst_ip lấy từ Host."""
        local_ip = request.host.partition(':')[0] or request.environ.get('SERVER_NAME', '')
        local_port = request.environ.get('SERVER_PORT')
        return dict(src_port=request.environ.get('REMOTE_PORT'),
                    dst_ip=local_ip, dst_port=int(local_port) if local_port else None,
                    user_agent=request.headers.get('User-Agent'),
                    http_method=request.method, http_uri=request.full_path.rstrip('?'),
                    http_headers="\n".join(f"{k}: {v}" for k, v in request.headers),
                    http_body=g.get('body'), session_id=g.session_id)

    @app.after_request
    def save_session(response):
        if g.new_session:
            response.set_cookie(SESSION_COOKIE, g.session_id, httponly=True, samesite='Lax')
        return response

    @app.after_request
    def log_other_requests(response):
        """Ghi mọi request mà route chưa tự ghi (404, 405, HEAD, OPTIONS, trang chủ...)."""
        if not g.get('logged'):
            try:
                log_event('http', 'http.request', request.remote_addr or '', **request_fields())
            except Exception as e:
                logger.error("Không thể ghi request HTTP: %s", e)
        return response

    @app.route('/')
    def index():
        return render_template('wp-admin.html')

    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        logger.info("Đăng nhập web từ %s: %s / %s", ip_address, username, password)

        # waitress đặt SERVER_NAME theo cấu hình server (thường 0.0.0.0), nên ưu tiên host mà client gọi tới
        log_event('http', 'http.login', ip_address, username=username, password=password,
                  attack_tag='sqli' if SQLI.search(username + ' ' + password) else None,
                  **request_fields())
        g.logged = True        # log_event nuốt lỗi CSDL nên tới được đây là đã xử lý xong

        if username == input_username and password == input_password:
            return 'DEEBOODAH!'
        return "Invalid username or password. Please Try Again."

    return app


def run_web_honeypot(host=settings.bind_address, port=settings.http_port,
                     input_username=settings.http_username, input_password=settings.http_password,
                     **serve_options):
    """Chạy honeypot HTTP bằng waitress; giới hạn tài nguyên lấy từ settings, serve_options ghi đè (dùng cho test)."""
    app = web_honeypot(input_username, input_password)
    options = {"threads": settings.http_threads, "connection_limit": settings.http_max_connections,
               "channel_timeout": settings.http_request_timeout,
               "max_request_body_size": settings.http_max_body_bytes}
    options.update(serve_options)
    logger.info("HTTP honeypot đang lắng nghe tại %s:%d (waitress: %d thread, tối đa %d kết nối)",
                host, port, options["threads"], options["connection_limit"])
    serve(app, host=host, port=port, **options)
