// Biểu đồ SVG thuần cho dashboard: cột chồng theo thời gian và thanh ngang chồng theo IP.
// Hai series cố định theo thứ tự palette (xanh dương = NIDS, cam = Honeypot), đã qua validate_palette.js.
// Nhãn đi qua textContent: tên IP/loại tấn công là dữ liệu không tin cậy, không bao giờ được render thành HTML.
const Charts = (() => {
  const NS = "http://www.w3.org/2000/svg";
  const SERIES = [{ key: "nids", name: "NIDS", color: "#2a78d6" }, { key: "honeypot", name: "Honeypot", color: "#eb6834" }];
  const INK = "#212529", MUTED = "#6c757d", GRID = "#e1e0d9", AXIS = "#adb5bd", WASH = "#f1f3f5";
  const redraws = new Set();

  function svgEl(tag, attrs, text) {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function htmlEl(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  // Chú giải (luôn có khi >= 2 series): ô vuông màu + tên bằng màu chữ thường
  function legend(box) {
    box.replaceChildren(...SERIES.map((s) => {
      const item = htmlEl("span", "legend-item");
      const sw = htmlEl("span", "sw"); sw.style.background = s.color;
      item.append(sw, s.name);
      return item;
    }));
  }

  // ── Tooltip: một div dùng chung, giá trị đậm, tên series phụ ──
  let tip;
  function showTip(x, y, title, rows) {
    if (!tip) { tip = htmlEl("div", "chart-tip"); document.body.append(tip); }
    tip.replaceChildren(htmlEl("div", "tip-title", title));
    for (const r of rows) {
      const row = htmlEl("div", "tip-row");
      const key = htmlEl("span", "tip-key"); key.style.background = r.color || "transparent";
      row.append(key, htmlEl("strong", "", r.value), htmlEl("span", "tip-name", r.name));
      tip.append(row);
    }
    tip.style.display = "block";
    const w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = Math.max(4, Math.min(x + 14, window.innerWidth - w - 4)) + "px";
    tip.style.top = Math.max(4, Math.min(y + 14, window.innerHeight - h - 4)) + "px";
  }
  function hideTip() { if (tip) tip.style.display = "none"; }
  function bindTip(target, onShow) {
    const at = (e) => {
      const r = target.getBoundingClientRect();
      onShow(e.clientX || r.left + r.width / 2, e.clientY || r.top + r.height / 2);
    };
    target.addEventListener("pointermove", at);
    target.addEventListener("focus", at);
    target.addEventListener("pointerleave", hideTip);
    target.addEventListener("blur", hideTip);
  }

  // Số nguyên đẹp cho trục: 0, step, 2·step... đủ phủ max
  function niceTicks(max) {
    if (max <= 0) return [0, 1];
    const raw = max / 4, mag = 10 ** Math.floor(Math.log10(raw));
    const step = Math.max(1, [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw));
    const ticks = [];
    for (let v = 0; ; v += step) { ticks.push(v); if (v >= max) break; }
    return ticks;
  }
  const compact = (n) => (n >= 1000 ? (n / 1000).toFixed(n % 1000 ? 1 : 0) + "K" : String(n));

  // Đỉnh cột bo 4px, chân phẳng nằm trên baseline
  const topRound = (x, y, w, h, r) => {
    r = Math.min(r, h, w / 2);
    return `M${x} ${y + h}V${y + r}Q${x} ${y} ${x + r} ${y}H${x + w - r}Q${x + w} ${y} ${x + w} ${y + r}V${y + h}Z`;
  };
  const rightRound = (x, y, w, h, r) => {
    r = Math.min(r, w, h / 2);
    return `M${x} ${y}H${x + w - r}Q${x + w} ${y} ${x + w} ${y + r}V${y + h - r}Q${x + w} ${y + h} ${x + w - r} ${y + h}H${x}Z`;
  };

  // Vẽ lại khi dữ liệu hoặc bề rộng đổi; giữ nguyên DOM khi không đổi để tooltip không bị chớp mỗi 2 giây
  function mount(box, data, draw) {
    box._data = data;
    const sig = JSON.stringify(data) + "|" + box.clientWidth;
    if (box._sig === sig) return;
    box._sig = sig;
    box.replaceChildren();
    hideTip();
    draw(box, data, Math.max(320, box.clientWidth));
    redraws.add(box);
  }
  window.addEventListener("resize", () => {
    for (const box of redraws) if (box.isConnected) mount(box, box._data, box._draw);
  });

  // ── Cột chồng theo thời gian: data = {step_seconds, buckets:[{t, nids, honeypot}]} ──
  function timeColumns(box, data) {
    box._draw = drawTime;
    mount(box, data, drawTime);
  }
  function drawTime(box, data, W) {
    const bs = data.buckets, n = bs.length;
    const total = (b) => b.nids + b.honeypot;
    const max = Math.max(0, ...bs.map(total));
    if (!max) { box.append(htmlEl("div", "empty", "Chưa có cảnh báo trong khoảng thời gian này")); return; }

    const H = 220, ml = 36, mr = 8, mt = 8, mb = 24, iw = W - ml - mr, ih = H - mt - mb;
    const ticks = niceTicks(max), top = ticks.at(-1);
    const Y = (v) => mt + ih - (v / top) * ih;
    const slot = iw / n, bw = Math.max(2, Math.min(24, slot - 2));
    const svg = svgEl("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img",
      "aria-label": `Cảnh báo theo thời gian, tối đa ${max} mỗi cột` });

    for (const t of ticks) {
      svg.append(svgEl("line", { x1: ml, x2: W - mr, y1: Y(t), y2: Y(t), stroke: t === 0 ? AXIS : GRID, "stroke-width": 1 }),
        svgEl("text", { x: ml - 6, y: Y(t) + 4, "text-anchor": "end", "font-size": 11, fill: MUTED }, compact(t)));
    }
    const every = Math.max(1, Math.ceil(n / 6));
    const hhmm = (iso) => new Date(iso).toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" });
    const hhmmss = (d) => d.toLocaleTimeString("vi-VN");
    bs.forEach((b, i) => {
      if (i % every === 0) svg.append(svgEl("text", { x: ml + i * slot + slot / 2, y: H - 6, "text-anchor": "middle", "font-size": 11, fill: MUTED }, hhmm(b.t)));
    });

    bs.forEach((b, i) => {
      const x = ml + i * slot + (slot - bw) / 2;
      const hn = (b.nids / top) * ih, hp = (b.honeypot / top) * ih;
      const band = svgEl("rect", { x: ml + i * slot, y: mt, width: slot, height: ih, fill: WASH, visibility: "hidden" });
      svg.append(band);
      // Khe 2px màu nền giữa hai đoạn: đoạn dưới ngắn đi 2px khi có đoạn trên
      if (b.nids) {
        const h = Math.max(1, hn - (b.honeypot ? 2 : 0)), y = mt + ih - hn;
        svg.append(b.honeypot ? svgEl("rect", { x, y: y + (hn - h), width: bw, height: h, fill: SERIES[0].color })
                              : svgEl("path", { d: topRound(x, y, bw, h, 4), fill: SERIES[0].color }));
      }
      if (b.honeypot) svg.append(svgEl("path", { d: topRound(x, mt + ih - hn - hp, bw, Math.max(1, hp), 4), fill: SERIES[1].color }));

      const hit = svgEl("rect", { x: ml + i * slot, y: mt, width: slot, height: ih, fill: "transparent", tabindex: 0,
        "aria-label": `${hhmm(b.t)}: ${b.nids} NIDS, ${b.honeypot} honeypot` });
      const start = new Date(b.t), end = new Date(start.getTime() + data.step_seconds * 1000);
      bindTip(hit, (px, py) => {
        band.setAttribute("visibility", "visible");
        showTip(px, py, `${hhmmss(start)} – ${hhmmss(end)}`, [
          { color: SERIES[0].color, name: "NIDS", value: b.nids },
          { color: SERIES[1].color, name: "Honeypot", value: b.honeypot },
          { name: "Tổng", value: total(b) }]);
      });
      hit.addEventListener("pointerleave", () => band.setAttribute("visibility", "hidden"));
      hit.addEventListener("blur", () => band.setAttribute("visibility", "hidden"));
      svg.append(hit);
    });
    box.append(svg);
  }

  // ── Thanh ngang chồng theo IP: rows = [{label, nids, honeypot, last}] ──
  function ipBars(box, rows) {
    box._draw = drawBars;
    mount(box, rows, drawBars);
  }
  function drawBars(box, rows, W) {
    if (!rows.length) { box.append(htmlEl("div", "empty", "Chưa có dữ liệu")); return; }
    const rowH = 30, bar = 16, ml = 116, mr = 44, H = rows.length * rowH + 4, iw = W - ml - mr;
    const max = Math.max(...rows.map((r) => r.nids + r.honeypot));
    const svg = svgEl("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Cảnh báo theo IP tấn công" });
    rows.forEach((r, i) => {
      const y = i * rowH + (rowH - bar) / 2, tot = r.nids + r.honeypot;
      const wn = (r.nids / max) * iw, wp = (r.honeypot / max) * iw;
      const band = svgEl("rect", { x: 0, y: i * rowH, width: W, height: rowH, fill: WASH, visibility: "hidden" });
      svg.append(band, svgEl("text", { x: ml - 8, y: y + bar / 2 + 4, "text-anchor": "end", "font-size": 12, fill: INK }, r.label));
      // Khe 2px giữa hai đoạn; đầu phải của đoạn ngoài cùng bo 4px, gốc trái phẳng
      if (r.nids) svg.append(r.honeypot ? svgEl("rect", { x: ml, y, width: Math.max(1, wn - 2), height: bar, fill: SERIES[0].color })
                                        : svgEl("path", { d: rightRound(ml, y, Math.max(1, wn), bar, 4), fill: SERIES[0].color }));
      if (r.honeypot) svg.append(svgEl("path", { d: rightRound(ml + wn, y, Math.max(1, wp), bar, 4), fill: SERIES[1].color }));
      svg.append(svgEl("text", { x: ml + wn + wp + 6, y: y + bar / 2 + 4, "font-size": 12, fill: INK }, tot));
      const hit = svgEl("rect", { x: 0, y: i * rowH, width: W, height: rowH, fill: "transparent", tabindex: 0,
        "aria-label": `${r.label}: ${r.nids} NIDS, ${r.honeypot} honeypot` });
      bindTip(hit, (px, py) => {
        band.setAttribute("visibility", "visible");
        showTip(px, py, r.label, [
          { color: SERIES[0].color, name: "NIDS", value: r.nids },
          { color: SERIES[1].color, name: "Honeypot", value: r.honeypot },
          { name: "Lần cuối", value: r.last }]);
      });
      hit.addEventListener("pointerleave", () => band.setAttribute("visibility", "hidden"));
      hit.addEventListener("blur", () => band.setAttribute("visibility", "hidden"));
      svg.append(hit);
    });
    box.append(svg);
  }

  return { legend, timeColumns, ipBars };
})();
