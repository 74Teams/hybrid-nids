FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    vsftpd \
    openssh-server \
    ncat \
    && rm -rf /var/lib/apt/lists/*

# OpenSSH trên Debian cần thư mục này tồn tại trước khi chạy sshd.
RUN mkdir -p /var/run/sshd

# sed không báo lỗi khi pattern không khớp dòng nào, nên phải grep lại kết quả
# để biết có cần echo append hay không (không dựa vào exit code của sed).
RUN sed -i 's/^#\?anonymous_enable=.*/anonymous_enable=YES/' /etc/vsftpd.conf \
    && grep -q '^anonymous_enable=YES' /etc/vsftpd.conf \
    || echo "anonymous_enable=YES" >> /etc/vsftpd.conf

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
