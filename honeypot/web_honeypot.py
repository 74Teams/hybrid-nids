import logging
import re

from flask import Flask, render_template, request

from .settings import settings
from .store import log_event

logger = logging.getLogger("nids.honeypot")

SQLI = re.compile(r"('|--|OR\s+\d|UNION|SELECT)", re.I)


def web_honeypot(input_username=settings.http_username, input_password=settings.http_password):
    app = Flask(__name__)

    @app.route('/')
    def index():
        return render_template('wp-admin.html')

    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        logger.info("Đăng nhập web từ %s: %s / %s", ip_address, username, password)

        local_ip, local_port = request.environ.get('SERVER_NAME', ''), request.environ.get('SERVER_PORT')
        log_event('http', 'http.login', ip_address,
                  src_port=request.environ.get('REMOTE_PORT'),
                  dst_ip=local_ip, dst_port=int(local_port) if local_port else None,
                  username=username, password=password,
                  user_agent=request.headers.get('User-Agent'),
                  http_method=request.method, http_uri=request.full_path.rstrip('?'),
                  attack_tag='sqli' if SQLI.search(username + ' ' + password) else None)

        if username == input_username and password == input_password:
            return 'DEEBOODAH!'
        return "Invalid username or password. Please Try Again."

    return app


def run_web_honeypot(host=settings.bind_address, port=settings.http_port,
                     input_username=settings.http_username, input_password=settings.http_password):
    app = web_honeypot(input_username, input_password)
    app.run(debug=False, port=port, host=host)
