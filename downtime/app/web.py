from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse


WEB_PORT = 8098


class WebDashboard:
    def __init__(
        self,
        store: Any,
        metrics_provider: Callable[[], dict[str, Any]],
        connectivity_provider: Callable[[], dict[str, bool | None]],
        host: str = "0.0.0.0",
        port: int = WEB_PORT,
    ) -> None:
        self.store = store
        self.metrics_provider = metrics_provider
        self.connectivity_provider = connectivity_provider
        self.server = ThreadingHTTPServer(
            (host, port),
            self._handler_class(),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.host = host
        self.port = port

    def start(self) -> None:
        self.thread.start()
        logging.info("Web dashboard listening on %s:%s", self.host, self.port)

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        dashboard = self

        class DashboardHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/") or "/"
                params = parse_qs(parsed.query)

                if path in {"/", "/index.html"}:
                    self._send_html(DASHBOARD_HTML)
                    return
                if path == "/api/summary":
                    self._send_json(
                        {
                            "metrics": dashboard.metrics_provider(),
                            "connectivity": format_connectivity(
                                dashboard.connectivity_provider()
                            ),
                            "server_time": utc_iso(),
                        }
                    )
                    return
                if path == "/api/daily":
                    days = clamp_query_int(params, "days", 30, 1, 90)
                    self._send_json(
                        {
                            "days": dashboard.store.calculate_daily_rollups(days),
                            "server_time": utc_iso(),
                        }
                    )
                    return
                if path == "/api/events":
                    limit = clamp_query_int(params, "limit", 60, 1, 250)
                    self._send_json(
                        {
                            "events": dashboard.store.list_recent_events(limit),
                            "server_time": utc_iso(),
                        }
                    )
                    return
                if path == "/api/health":
                    self._send_json({"status": "ok", "server_time": utc_iso()})
                    return

                self.send_error(404, "Not found")

            def log_message(self, fmt: str, *args: Any) -> None:
                logging.debug("Web dashboard: " + fmt, *args)

            def _send_html(self, payload: str) -> None:
                encoded = payload.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def _send_json(self, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        return DashboardHandler


def clamp_query_int(
    params: dict[str, list[str]], key: str, default: int, minimum: int, maximum: int
) -> int:
    try:
        value = int(params.get(key, [str(default)])[0])
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def format_connectivity(status: dict[str, bool | None]) -> dict[str, str]:
    return {
        "homeassistant_core": state_label(status.get("homeassistant_core")),
        "internet": state_label(status.get("internet")),
        "router": state_label(status.get("router")),
    }


def state_label(value: bool | None) -> str:
    if value is True:
        return "online"
    if value is False:
        return "offline"
    return "unknown"


def utc_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


DASHBOARD_HTML = r"""<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HA Uptime & Outage Monitor</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7fa;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #627083;
      --line: #dce3eb;
      --accent: #007f7a;
      --accent-soft: #dff3f0;
      --danger: #bc3b32;
      --danger-soft: #f8e5e2;
      --warning: #b36b00;
      --warning-soft: #fff0cf;
      --ok: #227a44;
      --shadow: 0 8px 28px rgba(24, 39, 75, 0.08);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-width: 320px;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.45;
    }

    header {
      background: var(--panel);
      border-bottom: 1px solid var(--line);
    }

    .shell {
      width: min(1280px, calc(100% - 32px));
      margin: 0 auto;
    }

    .topbar {
      min-height: 76px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }

    h1 {
      margin: 0;
      font-size: clamp(1.25rem, 2vw, 1.8rem);
      font-weight: 740;
      letter-spacing: 0;
    }

    .timestamp {
      color: var(--muted);
      font-size: 0.9rem;
      white-space: nowrap;
    }

    .button {
      appearance: none;
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--text);
      border-radius: 6px;
      min-height: 40px;
      padding: 0 14px;
      font: inherit;
      cursor: pointer;
    }

    .button:hover {
      border-color: #a9b6c5;
    }

    main {
      padding: 24px 0 32px;
    }

    .grid {
      display: grid;
      gap: 16px;
    }

    .metrics {
      grid-template-columns: repeat(5, minmax(0, 1fr));
    }

    .charts {
      grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.65fr);
      align-items: start;
      margin-top: 16px;
    }

    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .metric {
      min-height: 132px;
      padding: 18px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .metric-label,
    .section-title {
      color: var(--muted);
      font-size: 0.82rem;
      font-weight: 720;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .metric-value {
      margin-top: 12px;
      font-size: clamp(1.7rem, 3.6vw, 2.55rem);
      font-weight: 780;
      line-height: 1.05;
      letter-spacing: 0;
    }

    .metric-unit {
      color: var(--muted);
      font-size: 0.95rem;
      font-weight: 520;
    }

    .metric-sub {
      color: var(--muted);
      font-size: 0.88rem;
      min-height: 1.2em;
    }

    .panel-head {
      min-height: 58px;
      padding: 16px 18px 10px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      border-bottom: 1px solid var(--line);
    }

    .panel-body {
      padding: 16px 18px 18px;
    }

    canvas {
      display: block;
      width: 100%;
      height: 300px;
    }

    .stack {
      display: grid;
      gap: 16px;
    }

    .status-list {
      display: grid;
      gap: 10px;
    }

    .status-row {
      min-height: 52px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfe;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 10px;
      border-radius: 999px;
      font-size: 0.82rem;
      font-weight: 700;
      text-transform: uppercase;
    }

    .pill.ok {
      background: #dff4e7;
      color: var(--ok);
    }

    .pill.offline {
      background: var(--danger-soft);
      color: var(--danger);
    }

    .pill.unknown {
      background: #edf1f5;
      color: var(--muted);
    }

    .table-wrap {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 720px;
    }

    th,
    td {
      padding: 11px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      font-size: 0.92rem;
      vertical-align: top;
    }

    th {
      color: var(--muted);
      font-size: 0.78rem;
      font-weight: 720;
      text-transform: uppercase;
      letter-spacing: 0;
      background: #fbfcfe;
    }

    tbody tr:last-child td {
      border-bottom: 0;
    }

    .empty {
      color: var(--muted);
      padding: 18px;
    }

    .event-type {
      font-weight: 720;
    }

    .event-type.outage,
    .event-type.homeassistant_down,
    .event-type.internet_down,
    .event-type.router_down {
      color: var(--danger);
    }

    .event-type.homeassistant_up,
    .event-type.internet_up,
    .event-type.router_up {
      color: var(--ok);
    }

    .events {
      margin-top: 16px;
    }

    @media (max-width: 920px) {
      .metrics,
      .charts {
        grid-template-columns: 1fr 1fr;
      }

      .charts > .card:first-child,
      .events {
        grid-column: 1 / -1;
      }
    }

    @media (max-width: 640px) {
      .shell {
        width: min(100% - 20px, 1280px);
      }

      .topbar,
      .panel-head {
        align-items: flex-start;
        flex-direction: column;
      }

      .metrics,
      .charts {
        grid-template-columns: 1fr;
      }

      canvas {
        height: 240px;
      }

      .timestamp {
        white-space: normal;
      }
    }
  </style>
</head>
<body>
  <header>
    <div class="shell topbar">
      <div>
        <h1>HA Uptime & Outage Monitor</h1>
        <div class="timestamp" id="updatedAt">Aktualisierung ausstehend</div>
      </div>
      <button class="button" id="refreshButton" type="button">Aktualisieren</button>
    </div>
  </header>

  <main class="shell">
    <section class="grid metrics" aria-label="Kennzahlen">
      <article class="card metric">
        <div class="metric-label">System / Strom</div>
        <div>
          <div class="metric-value"><span id="downtime7d">0</span> <span class="metric-unit">min</span></div>
          <div class="metric-sub"><span id="outages7d">0</span> Lücken in 7 Tagen</div>
        </div>
      </article>
      <article class="card metric">
        <div class="metric-label">Home Assistant Core</div>
        <div>
          <div class="metric-value"><span id="haCoreOutage7d">0</span> <span class="metric-unit">min</span></div>
          <div class="metric-sub"><span id="haCoreOutageCount7d">0</span> Ausfälle in 7 Tagen</div>
        </div>
      </article>
      <article class="card metric">
        <div class="metric-label">Internet</div>
        <div>
          <div class="metric-value"><span id="internetOutage7d">0</span> <span class="metric-unit">min</span></div>
          <div class="metric-sub">getrennt vom Systemausfall</div>
        </div>
      </article>
      <article class="card metric">
        <div class="metric-label">Router</div>
        <div>
          <div class="metric-value"><span id="routerOutage7d">0</span> <span class="metric-unit">min</span></div>
          <div class="metric-sub">lokale Erreichbarkeit</div>
        </div>
      </article>
      <article class="card metric">
        <div class="metric-label">Starts / Reboots</div>
        <div>
          <div class="metric-value"><span id="addonStarts7d">0</span></div>
          <div class="metric-sub">Add-on-Starts in 7 Tagen</div>
        </div>
      </article>
    </section>

    <section class="grid charts">
      <article class="card">
        <div class="panel-head">
          <div class="section-title">Ausfallzeit pro Tag</div>
          <div class="timestamp">letzte 30 Tage</div>
        </div>
        <div class="panel-body">
          <canvas id="downtimeChart" width="980" height="360" aria-label="Ausfallzeit pro Tag"></canvas>
        </div>
      </article>

      <div class="stack">
        <article class="card">
          <div class="panel-head">
            <div class="section-title">Erreichbarkeit</div>
          </div>
          <div class="panel-body status-list">
            <div class="status-row">
              <strong>Home Assistant Core</strong>
              <span class="pill unknown" id="haCoreStatus">unknown</span>
            </div>
            <div class="status-row">
              <strong>Internet</strong>
              <span class="pill unknown" id="internetStatus">unknown</span>
            </div>
            <div class="status-row">
              <strong>Router</strong>
              <span class="pill unknown" id="routerStatus">unknown</span>
            </div>
            <div class="status-row">
              <strong>Add-on Uptime</strong>
              <span id="addonUptime">0 s</span>
            </div>
            <div class="status-row">
              <strong>Letzter Systemausfall</strong>
              <span id="lastWindow">keine Daten</span>
            </div>
          </div>
        </article>

        <article class="card">
          <div class="panel-head">
            <div class="section-title">Ausfälle 7 Tage</div>
          </div>
          <div class="panel-body">
            <canvas id="networkChart" width="420" height="300" aria-label="Ausfälle 7 Tage"></canvas>
          </div>
        </article>
      </div>
    </section>

    <section class="card events">
      <div class="panel-head">
        <div class="section-title">Letzte Ereignisse</div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Typ</th>
              <th>Start</th>
              <th>Ende</th>
              <th>Dauer</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody id="eventsBody">
            <tr><td class="empty" colspan="5">Keine Daten</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </main>

  <script>
    const els = {
      updatedAt: document.getElementById('updatedAt'),
      downtime7d: document.getElementById('downtime7d'),
      outages7d: document.getElementById('outages7d'),
      haCoreOutage7d: document.getElementById('haCoreOutage7d'),
      haCoreOutageCount7d: document.getElementById('haCoreOutageCount7d'),
      internetOutage7d: document.getElementById('internetOutage7d'),
      routerOutage7d: document.getElementById('routerOutage7d'),
      addonStarts7d: document.getElementById('addonStarts7d'),
      lastWindow: document.getElementById('lastWindow'),
      addonUptime: document.getElementById('addonUptime'),
      haCoreStatus: document.getElementById('haCoreStatus'),
      internetStatus: document.getElementById('internetStatus'),
      routerStatus: document.getElementById('routerStatus'),
      eventsBody: document.getElementById('eventsBody')
    };

    const downtimeChart = document.getElementById('downtimeChart');
    const networkChart = document.getElementById('networkChart');
    const refreshButton = document.getElementById('refreshButton');

    async function loadDashboard() {
      refreshButton.disabled = true;
      try {
        const [summary, daily, events] = await Promise.all([
          fetchJson('/api/summary'),
          fetchJson('/api/daily?days=30'),
          fetchJson('/api/events?limit=60')
        ]);
        renderSummary(summary);
        drawDowntimeChart(downtimeChart, daily.days || []);
        drawNetworkChart(networkChart, summary.metrics || {});
        renderEvents(events.events || []);
      } catch (err) {
        els.updatedAt.textContent = 'Fehler beim Laden';
        console.error(err);
      } finally {
        refreshButton.disabled = false;
      }
    }

    async function fetchJson(url) {
      const response = await fetch(url, {cache: 'no-store'});
      if (!response.ok) {
        throw new Error(`${url}: ${response.status}`);
      }
      return response.json();
    }

    function renderSummary(summary) {
      const metrics = summary.metrics || {};
      const connectivity = summary.connectivity || {};
      els.updatedAt.textContent = `Zuletzt aktualisiert: ${formatDateTime(metrics.updated_at || summary.server_time)}`;
      els.downtime7d.textContent = number(metrics.downtime_7d_minutes);
      els.outages7d.textContent = number(metrics.outage_count_7d, 0);
      els.haCoreOutage7d.textContent = number(metrics.homeassistant_outage_7d_minutes);
      els.haCoreOutageCount7d.textContent = number(metrics.homeassistant_outage_count_7d, 0);
      els.internetOutage7d.textContent = number(metrics.internet_outage_7d_minutes);
      els.routerOutage7d.textContent = number(metrics.router_outage_7d_minutes);
      els.addonStarts7d.textContent = number(metrics.addon_restart_count_7d, 0);
      els.lastWindow.textContent = formatWindow(metrics.last_outage_start, metrics.last_outage_end);
      els.addonUptime.textContent = formatDuration(metrics.addon_uptime_seconds || 0);
      setPill(els.haCoreStatus, connectivity.homeassistant_core);
      setPill(els.internetStatus, connectivity.internet);
      setPill(els.routerStatus, connectivity.router);
    }

    function setPill(element, state) {
      element.classList.remove('ok', 'offline', 'unknown');
      const normalized = state || 'unknown';
      element.textContent = normalized;
      element.classList.add(normalized === 'online' ? 'ok' : normalized);
    }

    function drawDowntimeChart(canvas, days) {
      const ctx = setupCanvas(canvas);
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      const padding = {top: 20, right: 18, bottom: 42, left: 48};
      clear(ctx, width, height);
      drawAxes(ctx, width, height, padding);

      const series = [
        {key: 'downtime_minutes', label: 'System', color: '#bc3b32'},
        {key: 'homeassistant_outage_minutes', label: 'HA Core', color: '#007f7a'},
        {key: 'internet_outage_minutes', label: 'Internet', color: '#b36b00'},
        {key: 'router_outage_minutes', label: 'Router', color: '#2f6fad'}
      ];
      const totals = days.map(day => series.reduce((sum, item) => sum + Number(day[item.key] || 0), 0));
      const maxValue = Math.max(1, ...totals);
      const plotWidth = width - padding.left - padding.right;
      const plotHeight = height - padding.top - padding.bottom;
      const gap = 3;
      const barWidth = Math.max(4, (plotWidth / Math.max(1, days.length)) - gap);

      days.forEach((day, index) => {
        const x = padding.left + index * (plotWidth / days.length) + gap / 2;
        let yBase = padding.top + plotHeight;
        let hasValue = false;
        series.forEach(item => {
          const value = Number(day[item.key] || 0);
          if (value <= 0) {
            return;
          }
          hasValue = true;
          const barHeight = Math.max(3, (value / maxValue) * plotHeight);
          yBase -= barHeight;
          ctx.fillStyle = item.color;
          ctx.fillRect(x, yBase, barWidth, barHeight);
        });
        if (!hasValue) {
          ctx.fillStyle = '#dce3eb';
          ctx.fillRect(x, padding.top + plotHeight - 1, barWidth, 1);
        }
      });

      ctx.fillStyle = '#627083';
      ctx.font = '12px system-ui, sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(`${maxValue.toFixed(maxValue >= 10 ? 0 : 1)} min`, 8, padding.top + 6);
      ctx.fillText(labelDay(days[0]), padding.left, height - 14);
      ctx.textAlign = 'right';
      ctx.fillText(labelDay(days[days.length - 1]), width - padding.right, height - 14);

      let legendX = padding.left;
      series.forEach(item => {
        ctx.fillStyle = item.color;
        ctx.fillRect(legendX, 8, 10, 10);
        ctx.fillStyle = '#627083';
        ctx.textAlign = 'left';
        ctx.fillText(item.label, legendX + 14, 17);
        legendX += 84;
      });
    }

    function drawNetworkChart(canvas, metrics) {
      const ctx = setupCanvas(canvas);
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      clear(ctx, width, height);
      const data = [
        {label: 'System', value: Number(metrics.downtime_7d_minutes || 0), color: '#bc3b32'},
        {label: 'HA Core', value: Number(metrics.homeassistant_outage_7d_minutes || 0), color: '#007f7a'},
        {label: 'Internet', value: Number(metrics.internet_outage_7d_minutes || 0), color: '#b36b00'},
        {label: 'Router', value: Number(metrics.router_outage_7d_minutes || 0), color: '#2f6fad'}
      ];
      const maxValue = Math.max(1, ...data.map(item => item.value));
      const barArea = width - 118;
      data.forEach((item, index) => {
        const y = 34 + index * 52;
        const barWidth = Math.max(item.value > 0 ? 3 : 0, (item.value / maxValue) * barArea);
        ctx.fillStyle = '#edf1f5';
        ctx.fillRect(90, y, barArea, 24);
        ctx.fillStyle = item.color;
        ctx.fillRect(90, y, barWidth, 24);
        ctx.fillStyle = '#17202a';
        ctx.font = '13px system-ui, sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText(item.label, 0, y + 17);
        ctx.textAlign = 'right';
        ctx.fillText(`${number(item.value)} min`, width, y + 17);
      });
    }

    function drawAxes(ctx, width, height, padding) {
      ctx.strokeStyle = '#dce3eb';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padding.left, padding.top);
      ctx.lineTo(padding.left, height - padding.bottom);
      ctx.lineTo(width - padding.right, height - padding.bottom);
      ctx.stroke();
      ctx.strokeStyle = '#eef2f6';
      for (let i = 1; i <= 4; i += 1) {
        const y = padding.top + ((height - padding.top - padding.bottom) / 4) * i;
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(width - padding.right, y);
        ctx.stroke();
      }
    }

    function setupCanvas(canvas) {
      const ratio = window.devicePixelRatio || 1;
      const width = Math.max(1, canvas.clientWidth);
      const height = Math.max(1, canvas.clientHeight);
      canvas.width = Math.floor(width * ratio);
      canvas.height = Math.floor(height * ratio);
      const ctx = canvas.getContext('2d');
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      return ctx;
    }

    function clear(ctx, width, height) {
      ctx.clearRect(0, 0, width, height);
    }

    function renderEvents(events) {
      if (!events.length) {
        els.eventsBody.innerHTML = '<tr><td class="empty" colspan="5">Keine Daten</td></tr>';
        return;
      }
      els.eventsBody.innerHTML = events.map(event => `
        <tr>
          <td><span class="event-type ${escapeHtml(event.type)}">${escapeHtml(eventLabel(event.type))}</span></td>
          <td>${formatDateTime(event.start_ts)}</td>
          <td>${formatDateTime(event.end_ts)}</td>
          <td>${formatDuration(event.duration_seconds)}</td>
          <td>${formatMetadata(event.metadata)}</td>
        </tr>
      `).join('');
    }

    function eventLabel(type) {
      const labels = {
        outage: 'System-/Stromausfall',
        addon_start: 'Add-on Start/Reboot',
        internet_down: 'Internet unterbrochen',
        internet_up: 'Internet wieder online',
        router_down: 'Router unterbrochen',
        router_up: 'Router wieder online',
        homeassistant_down: 'Home Assistant Core offline',
        homeassistant_up: 'Home Assistant Core online'
      };
      return labels[type] || type;
    }

    function formatMetadata(metadata) {
      if (!metadata || !Object.keys(metadata).length) {
        return '';
      }
      return escapeHtml(Object.entries(metadata).map(([key, value]) => `${key}: ${value}`).join(', '));
    }

    function formatWindow(start, end) {
      if (!start || start === 'none') {
        return 'keine Daten';
      }
      return `${formatDateTime(start)} - ${formatDateTime(end)}`;
    }

    function formatDateTime(value) {
      if (!value || value === 'none') {
        return '-';
      }
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) {
        return value;
      }
      return date.toLocaleString([], {dateStyle: 'short', timeStyle: 'medium'});
    }

    function formatDuration(seconds) {
      const total = Math.max(0, Number(seconds || 0));
      if (total < 60) {
        return `${Math.round(total)} s`;
      }
      const minutes = Math.floor(total / 60);
      if (minutes < 60) {
        return `${minutes} min`;
      }
      const hours = Math.floor(minutes / 60);
      const rest = minutes % 60;
      return `${hours} h ${rest} min`;
    }

    function labelDay(day) {
      if (!day || !day.date) {
        return '';
      }
      const date = new Date(`${day.date}T00:00:00Z`);
      return date.toLocaleDateString([], {month: '2-digit', day: '2-digit'});
    }

    function number(value, digits = 2) {
      const parsed = Number(value || 0);
      return parsed.toLocaleString([], {
        minimumFractionDigits: digits,
        maximumFractionDigits: digits
      });
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    refreshButton.addEventListener('click', loadDashboard);
    window.addEventListener('resize', () => loadDashboard());
    loadDashboard();
    setInterval(loadDashboard, 60000);
  </script>
</body>
</html>"""
