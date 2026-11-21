// Cập nhật tức thì: WebSocket /api/alerts/ws chỉ báo "có cảnh báo mới", dữ liệu vẫn tải lại qua REST bằng `load`.
// Mất WebSocket (Redis tắt, API khởi động lại) thì tự poll mỗi `pollMs` và nối lại với backoff; trả về hàm dừng.
// onMode("live" | "poll") báo chế độ hiện tại, không bắt buộc.
function liveAlerts(load, pollMs, onMode) {
  const SLOW_POLL = 30000;     // khi đang live vẫn tải lại thưa: biểu đồ timeline trượt theo giờ, tab khác xoá cảnh báo không phát tín hiệu
  const THROTTLE = 500;        // gộp nhiều tín hiệu liên tiếp, tối đa 2 lần tải mỗi giây
  const MAX_BACKOFF = 60000;
  let ws = null, pollTimer = null, retryTimer = null, timer = null;
  let backoff = 5000, last = 0, running = false, dirty = false, stopped = false;

  function trigger() {
    dirty = true;
    if (timer || running) return;
    timer = setTimeout(async () => {
      timer = null; last = Date.now(); dirty = false; running = true;
      try { await load(); } catch (e) { /* load tự báo lỗi kết nối */ } finally { running = false; }
      if (dirty && !stopped) trigger();
    }, Math.max(0, last + THROTTLE - Date.now()));
  }
  function setPoll(ms) {
    clearInterval(pollTimer);
    pollTimer = setInterval(trigger, ms);
  }
  function mode(m) { if (onMode) onMode(m); }
  function retry() {
    if (stopped) return;
    retryTimer = setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, MAX_BACKOFF);
  }
  function connect() {
    if (stopped) return;
    try {
      ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/api/alerts/ws");
    } catch (e) { retry(); return; }
    ws.onopen = () => { backoff = 5000; setPoll(SLOW_POLL); mode("live"); trigger(); };
    ws.onmessage = trigger;
    ws.onclose = () => { ws = null; if (stopped) return; setPoll(pollMs); mode("poll"); retry(); };
  }

  setPoll(pollMs);
  mode("poll");
  trigger();
  connect();
  return () => {
    stopped = true;
    clearInterval(pollTimer); clearTimeout(retryTimer); clearTimeout(timer);
    if (ws) ws.close();
  };
}
