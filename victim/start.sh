#!/bin/sh
# Khởi động các dịch vụ nền của victim rồi chạy nginx foreground làm PID 1.
vsftpd /etc/vsftpd.conf &
/usr/sbin/sshd &
ncat -lk -p 4444 >/dev/null &
ncat -lk -p 3333 >/dev/null &
exec nginx -g "daemon off;"
