# Đặt PYTHONPATH để chạy các service và công cụ từ gốc repo (bash/zsh).
# Dùng một lần cho mỗi terminal:  source scripts/env.sh
_root="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
export PYTHONPATH="$_root/common/core/src:$_root/services/sensor/src:$_root/services/honeypot/src:$_root/services/redirector/src:$_root/services/dashboard/src:$_root/common"
echo "PYTHONPATH đã được đặt cho $_root"
unset _root
