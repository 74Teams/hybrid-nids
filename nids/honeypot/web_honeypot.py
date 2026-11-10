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

    @app.after_request
    def save_session(response):
        if g.new_session:
            response.set_cookie(SESSION_COOKIE, g.session_id, httponly=True, samesite='Lax')
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
        local_ip = request.host.partition(':')[0] or request.environ.get('SERVER_NAME', '')
        local_port = request.environ.get('SERVER_PORT')
        log_event('http', 'http.login', ip_address,
                  src_port=request.environ.get('REMOTE_PORT'),
                  dst_ip=local_ip, dst_port=int(local_port) if local_port else None,
                  username=username, password=password,
                  user_agent=request.headers.get('User-Agent'),
                  http_method=request.method, http_uri=request.full_path.rstrip('?'),
                  attack_tag='sqli' if SQLI.search(username + ' ' + password) else None,
                  session_id=g.session_id)

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
