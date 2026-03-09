import os
import io
import uuid
import base64
import html
import json
import re
import ipaddress
import shutil
import tarfile
import tempfile
import threading
import time
import pytz
import pandas as pd
import plotly.express as px
from flask import Flask, request, Response, jsonify, render_template_string, send_file
from dateutil import parser as date_parser
from elasticsearch import Elasticsearch, helpers
from influxdb import InfluxDBClient
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from neo4j import GraphDatabase
from parsers.palo_alto_parser import PaloAltoParser
from parsers.fortigate_parser import FortigateParser
from parsers.sonicwall_parser import SonicwallParser
from parsers.cisco_ftd_parser import CiscoFTDParser
from parsers.checkpoint_parser import CheckpointParser
from parsers.meraki_parser import MerakiParser
from parsers.unifi_parser import UnifiParser
from parsers.juniper_parser import JuniperParser
from parsers.watchguard_parser import WatchguardParser
from parsers.sophos_utm_parser import SophosUTMParser
from parsers.sophos_xgs_parser import SophosXGSParser
from parsers.netscaler_parser import NetscalerParser

app = Flask(__name__)
app.secret_key = "REPLACE_ME"
DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(DIR, "uploads")
os.makedirs(UPLOADS, exist_ok=True)
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "testuser")
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
PARSERS = {
    "palo_alto": PaloAltoParser,
    "fortigate": FortigateParser,
    "sonicwall": SonicwallParser,
    "cisco_ftd": CiscoFTDParser,
    "checkpoint": CheckpointParser,
    "meraki": MerakiParser,
    "unifi": UnifiParser,
    "juniper": JuniperParser,
    "watchguard": WatchguardParser,
    "sophos_utm": SophosUTMParser,
    "sophos_xgs": SophosXGSParser,
    "netscaler": NetscalerParser  # NEW
}
CASE_PARSE_STATUS = {}
CASE_DATA_CACHE = {}
CASE_STATE_LOCK = threading.Lock()
PLOTLY_DIV_ID_RE = re.compile(r'<div id="([^"]+)" class="plotly-graph-div"')
CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SEVERITY_SORT = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
UNKNOWN_VALUE_TOKENS = {
    "",
    "unknown",
    "unk",
    "none",
    "null",
    "nil",
    "n/a",
    "na",
    "-",
    "--",
    "other",
    "misc",
    "miscellaneous",
    "notset",
    "unset",
    "n a",
    "not applicable",
    "not set",
}
CANONICAL_LOG_CATEGORY_ORDER = [
    "threat",
    "malware",
    "authentication",
    "vpn",
    "traffic",
    "web",
    "dns",
    "configuration",
    "system",
    "ha",
    "routing",
    "wireless",
    "unknown",
]
CANONICAL_LOG_CATEGORIES = set(CANONICAL_LOG_CATEGORY_ORDER) - {"unknown"}
LOG_CATEGORY_ALIASES = {
    "appfw": "threat",
    "attack": "threat",
    "anomaly": "threat",
    "security": "threat",
    "ids": "threat",
    "ips": "threat",
    "idp": "threat",
    "utm": "threat",
    "aaa": "authentication",
    "auth": "authentication",
    "login": "authentication",
    "logout": "authentication",
    "userid": "authentication",
    "user_id": "authentication",
    "globalprotect": "vpn",
    "ipsec": "vpn",
    "ike": "vpn",
    "sslvpn": "vpn",
    "nsvpn": "vpn",
    "tunnel": "vpn",
    "network": "traffic",
    "flow": "traffic",
    "session": "traffic",
    "connection": "traffic",
    "packet": "traffic",
    "firewall": "traffic",
    "rt_flow": "traffic",
    "url": "web",
    "proxy": "web",
    "http": "web",
    "https": "web",
    "event": "system",
    "health": "system",
    "daemon": "system",
    "chassis": "system",
    "admin": "configuration",
    "audit": "configuration",
    "config": "configuration",
    "command": "configuration",
    "cmd": "configuration",
    "change": "configuration",
    "cluster": "ha",
    "failover": "ha",
    "route": "routing",
    "bgp": "routing",
    "ospf": "routing",
    "wifi": "wireless",
    "wlan": "wireless",
    "ssid": "wireless",
}
CANONICAL_OUTCOME_ORDER = ["blocked", "failed", "detected", "allowed", "success", "unknown"]
CANONICAL_OUTCOMES = set(CANONICAL_OUTCOME_ORDER) - {"unknown"}
OUTCOME_ALIASES = {
    "allow": "allowed",
    "accept": "allowed",
    "permit": "allowed",
    "pass": "allowed",
    "session_create": "allowed",
    "deny": "blocked",
    "denied": "blocked",
    "drop": "blocked",
    "reject": "blocked",
    "block": "blocked",
    "quarantine": "blocked",
    "reset": "blocked",
    "auth_fail": "failed",
    "login_fail": "failed",
    "failure": "failed",
    "error": "failed",
    "invalid": "failed",
    "timeout": "failed",
    "auth_success": "success",
    "login_success": "success",
    "ok": "success",
    "detector": "detected",
    "alert": "detected",
    "threat": "detected",
}
IPV4_TEXT_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SEVERITY_ALIAS_MAP = {
    "EMERG": "CRITICAL",
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "ERR": "HIGH",
    "ERROR": "HIGH",
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "NOTICE": "LOW",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "INFO": "INFO",
    "INFORMATION": "INFO",
    "DEBUG": "INFO",
}
PROTOCOL_ALIAS_MAP = {
    "TCP": "TCP",
    "UDP": "UDP",
    "ICMP": "ICMP",
    "ICMPV6": "ICMPV6",
    "GRE": "GRE",
    "ESP": "ESP",
    "AH": "AH",
    "SCTP": "SCTP",
    "TLS": "TLS",
    "SSL": "TLS",
    "HTTP": "HTTP",
    "HTTPS": "HTTPS",
    "DNS": "DNS",
    "6": "TCP",
    "17": "UDP",
    "1": "ICMP",
    "58": "ICMPV6",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "132": "SCTP",
}
ARCHIVE_PARSEABLE_EXTENSIONS = {".log", ".txt", ".csv", ".tsv"}

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>{{ title }}</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      color-scheme: light dark;
      --bg: #ecf1f8;
      --bg-a: rgba(53, 98, 173, 0.20);
      --bg-b: rgba(109, 174, 113, 0.16);
      --panel: #f9fbff;
      --panel-soft: #f3f7ff;
      --border: #8aa7cd;
      --accent: #0d5ac3;
      --accent-strong: #073f87;
      --text: #13253f;
      --muted: #4d6788;
      --input-bg: #ffffff;
      --input-border: #8aa7cd;
      --table-head: #e5eefc;
      --table-border: #c7d6ef;
      --table-head-text: #073f87;
      --table-body-bg: #ffffff;
      --table-body-alt: #edf4ff;
      --table-cell-text: #13253f;
      --button-text: #f4fbff;
      --button-start: #0d5ac3;
      --button-end: #1f7bde;
      --shadow: 0 8px 30px rgba(32, 62, 103, 0.15);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #070b10;
        --bg-a: rgba(18, 53, 41, 0.60);
        --bg-b: rgba(22, 33, 56, 0.60);
        --panel: #0e1724;
        --panel-soft: #101f31;
        --border: #1e7b63;
        --accent: #30f2b3;
        --accent-strong: #53ffce;
        --text: #d8fff2;
        --muted: #86b9a8;
        --input-bg: #0b1521;
        --input-border: #236f5c;
        --table-head: #102133;
        --table-border: #1b6654;
        --table-head-text: #53ffce;
        --table-body-bg: #0d1a2a;
        --table-body-alt: #132238;
        --table-cell-text: #d8fff2;
        --button-text: #072518;
        --button-start: #53ffce;
        --button-end: #2ee7aa;
        --shadow: 0 8px 30px rgba(3, 12, 10, 0.45);
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background:
        radial-gradient(1000px 300px at 0% 0%, var(--bg-a) 0%, transparent 72%),
        radial-gradient(900px 260px at 100% 0%, var(--bg-b) 0%, transparent 68%),
        var(--bg);
      color: var(--text);
      font-family: "Consolas", "Monaco", monospace;
    }
    a { color: var(--accent); }
    .container {
      width: min(1400px, 96vw);
      margin: 0 auto;
      padding: 20px 0 36px;
    }
    header {
      background: linear-gradient(140deg, var(--panel-soft), var(--panel));
      border: 1px solid var(--border);
      border-radius: 14px;
      margin-bottom: 18px;
      padding: 14px 18px;
      box-shadow: var(--shadow);
    }
    header h1 {
      margin: 0 0 8px;
      font-size: clamp(1.2rem, 2vw, 1.7rem);
      letter-spacing: 0.03em;
    }
    nav a {
      margin-right: 16px;
      text-decoration: none;
      color: var(--accent);
    }
    nav a:hover { text-decoration: underline; }
    h2, h3 { margin: 16px 0 12px; }
    .case-box, .panel {
      background: linear-gradient(170deg, color-mix(in srgb, var(--panel-soft) 92%, transparent), color-mix(in srgb, var(--panel) 92%, transparent));
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      margin: 10px 0;
      box-shadow: var(--shadow);
    }
    input, select {
      width: 100%;
      margin: 6px 0;
      padding: 10px 12px;
      color: var(--text);
      background: var(--input-bg);
      border: 1px solid var(--input-border);
      border-radius: 8px;
    }
    .button {
      margin-top: 8px;
      padding: 10px 16px;
      color: var(--button-text);
      font-weight: 700;
      border: 0;
      border-radius: 9px;
      background: linear-gradient(110deg, var(--button-start), var(--button-end));
      cursor: pointer;
    }
    .button.secondary {
      background: transparent;
      color: var(--accent);
      border: 1px solid var(--accent);
    }
    .button:hover { filter: brightness(1.05); }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .stat-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
    }
    .stat-card .label {
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .stat-card .value {
      margin-top: 3px;
      font-size: 1.25rem;
      font-weight: 700;
    }
    .chart-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }
    .chart-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      min-height: 260px;
      box-shadow: var(--shadow);
    }
    .chart-card.plotly-filterable {
      cursor: crosshair;
    }
    .chart-title {
      margin: 0 0 8px;
      color: var(--muted);
      font-size: 0.9rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .scroll-box {
      max-height: 440px;
      overflow-y: auto;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 8px;
      margin-bottom: 14px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 12px;
      font-size: 0.9rem;
    }
    th, td {
      border: 1px solid var(--table-border);
      padding: 7px 10px;
      text-align: left;
    }
    td {
      color: var(--table-cell-text);
      background: var(--table-body-bg);
    }
    th {
      background: var(--table-head);
      color: var(--table-head-text);
      position: sticky;
      top: 0;
      z-index: 1;
    }
    .filter-hint {
      margin: 4px 0 10px;
      font-size: 0.85rem;
      color: var(--muted);
    }
    .quick-filter-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
    }
    .quick-filter {
      border: 1px solid var(--input-border);
      background: color-mix(in srgb, var(--panel-soft) 90%, transparent);
      color: var(--text);
      border-radius: 999px;
      padding: 6px 12px;
      font-size: 0.82rem;
      cursor: pointer;
    }
    .quick-filter:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    .quick-filter.active {
      border-color: var(--accent);
      background: color-mix(in srgb, var(--accent) 20%, var(--panel-soft) 80%);
      color: var(--accent-strong);
      font-weight: 700;
    }
    .loading-wrap {
      text-align: center;
      padding: 20px;
    }
    .progress-track {
      width: min(640px, 90%);
      height: 12px;
      margin: 12px auto;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: color-mix(in srgb, var(--panel-soft) 80%, transparent);
      overflow: hidden;
    }
    .progress-fill {
      width: 0%;
      height: 100%;
      background: linear-gradient(90deg, var(--button-start), var(--button-end));
      transition: width 0.5s ease;
    }
    .muted {
      color: var(--muted);
    }
    @media (max-width: 700px) {
      .chart-grid { grid-template-columns: 1fr; }
      .container { width: 94vw; }
    }
  </style>
  {{ datatables|safe }}
</head>
<body>
  <div class="container">
    <header>
      <h1>{{ header }}</h1>
      <nav>
        <a href="/">Home</a>
      </nav>
    </header>
    <main>
      {{ content|safe }}
    </main>
  </div>
</body>
</html>
"""

DATATABLES = """
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.25/css/jquery.dataTables.css">
<script src="https://code.jquery.com/jquery-3.5.1.js"></script>
<script src="https://cdn.datatables.net/1.10.25/js/jquery.dataTables.js"></script>
<style>
  .dataTables_wrapper { color: var(--text) !important; }
  .dataTables_wrapper .dataTables_length,
  .dataTables_wrapper .dataTables_filter,
  .dataTables_wrapper .dataTables_info,
  .dataTables_wrapper .dataTables_paginate {
    color: var(--text) !important;
  }
  .dataTables_wrapper .dataTables_filter input,
  .dataTables_wrapper .dataTables_length select {
    color: var(--text) !important;
    background: var(--input-bg) !important;
    border: 1px solid var(--input-border) !important;
  }
  .dataTables_wrapper .dataTables_paginate .paginate_button {
    color: var(--accent) !important;
  }
  table.dataTable thead th,
  table.dataTable thead td {
    background: var(--table-head) !important;
    color: var(--table-head-text) !important;
    border-color: var(--table-border) !important;
  }
  table.dataTable tbody td {
    color: var(--table-cell-text) !important;
    background-color: var(--table-body-bg) !important;
    border-color: var(--table-border) !important;
  }
  table.dataTable.stripe tbody tr.odd > *,
  table.dataTable.display tbody tr.odd > * {
    background-color: var(--table-body-alt) !important;
    color: var(--table-cell-text) !important;
  }
  table.dataTable.stripe tbody tr.even > *,
  table.dataTable.display tbody tr.even > * {
    background-color: var(--table-body-bg) !important;
    color: var(--table-cell-text) !important;
  }
  table.dataTable.display tbody tr:hover > * {
    background-color: color-mix(in srgb, var(--table-body-alt) 78%, var(--accent) 22%) !important;
  }
</style>
<script>
  $(document).ready(function() {
    const tableEl = document.getElementById('logsTable');
    if (!tableEl) return;

    const primaryCol = Number(tableEl.dataset.orderCol || 0);
    const primaryDir = tableEl.dataset.orderDir || 'asc';
    const secondaryRaw = tableEl.dataset.orderSecondaryCol;
    const secondaryDir = tableEl.dataset.orderSecondaryDir || 'desc';
    const order = [[Number.isNaN(primaryCol) ? 0 : primaryCol, primaryDir]];

    if (secondaryRaw !== undefined && secondaryRaw !== "") {
      const secondaryCol = Number(secondaryRaw);
      if (!Number.isNaN(secondaryCol) && secondaryCol !== primaryCol) {
        order.push([secondaryCol, secondaryDir]);
      }
    }

    const logsTable = $('#logsTable').DataTable({
      pageLength: 25,
      order: order,
      autoWidth: false,
      lengthMenu: [10, 25, 50, 100]
    });

    let columnMap = {};
    const mapEl = document.getElementById('logsTableColumnMap');
    if (mapEl) {
      try {
        columnMap = JSON.parse(mapEl.textContent || "{}");
      } catch (_err) {
        columnMap = {};
      }
    }

    const activeFilterEl = document.getElementById('activeFilter');
    const clearBtn = document.getElementById('clearTableFilters');
    const quickFilterButtons = Array.from(document.querySelectorAll('[data-quick-filter-column]'));

    function setFilterMessage(text) {
      if (activeFilterEl) activeFilterEl.textContent = text;
    }

    function resetTableFilters(drawTable) {
      logsTable.columns().every(function () {
        this.search('');
      });
      logsTable.search('');
      if (drawTable) logsTable.draw();
    }

    function clearGraphFilters() {
      resetTableFilters(true);
      setFilterMessage('No graph filters active.');
      quickFilterButtons.forEach((btn) => btn.classList.remove('active'));
    }

    function applyGraphFilter(columnKey, value) {
      const columnIdx = columnMap[columnKey];
      if (columnIdx === undefined) return;
      const cleaned = String(value === undefined || value === null ? '' : value).trim();
      if (!cleaned || cleaned.toLowerCase() === 'other') return;

      resetTableFilters(false);
      const pattern = '^' + $.fn.dataTable.util.escapeRegex(cleaned) + '$';
      logsTable.column(columnIdx).search(pattern, true, false).draw();
      setFilterMessage('Filter: ' + columnKey + ' = ' + cleaned);
      quickFilterButtons.forEach((btn) => btn.classList.remove('active'));
    }

    function applyQuickFilter(columnKey, pattern, label, activeBtn) {
      const columnIdx = columnMap[columnKey];
      if (columnIdx === undefined || !pattern) return;
      resetTableFilters(false);
      logsTable.column(columnIdx).search(pattern, true, false).draw();
      setFilterMessage('Quick filter: ' + label);
      quickFilterButtons.forEach((btn) => btn.classList.remove('active'));
      if (activeBtn) activeBtn.classList.add('active');
    }

    if (clearBtn) {
      clearBtn.addEventListener('click', clearGraphFilters);
    }

    quickFilterButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const columnKey = btn.dataset.quickFilterColumn || '';
        const pattern = btn.dataset.quickFilterPattern || '';
        const label = btn.dataset.quickFilterLabel || (columnKey + ' matches ' + pattern);
        applyQuickFilter(columnKey, pattern, label, btn);
      });
    });

    document.querySelectorAll('.chart-card[data-plotly-id]').forEach((card) => {
      const plotlyId = card.dataset.plotlyId || '';
      const filterColumn = card.dataset.filterColumn || '';
      const filterSource = card.dataset.filterSource || 'auto';

      if (!plotlyId || !filterColumn) return;
      const plotDiv = document.getElementById(plotlyId);
      if (!plotDiv || typeof plotDiv.on !== 'function') return;

      card.classList.add('plotly-filterable');
      plotDiv.on('plotly_click', (eventData) => {
        if (!eventData || !eventData.points || !eventData.points.length) return;
        const point = eventData.points[0];
        let value = '';

        if (filterSource === 'trace') {
          value = (point.data && point.data.name) || (point.fullData && point.fullData.name) || '';
        } else if (filterSource === 'label') {
          value = point.label !== undefined ? point.label : '';
        } else if (filterSource === 'x') {
          value = point.x !== undefined ? point.x : '';
        } else {
          value = point.label !== undefined
            ? point.label
            : ((point.data && point.data.name) || (point.fullData && point.fullData.name) || (point.x !== undefined ? point.x : ''));
        }

        applyGraphFilter(filterColumn, value);
      });
    });
  });
</script>
"""

def render_page(title, header, content, use_datatables=False):
    dt = DATATABLES if use_datatables else ""
    return render_template_string(BASE_TEMPLATE, title=title, header=header, content=content, datatables=dt)


def resolve_case_sidecar_path(case_id, sidecar_name):
    safe_case_id = str(case_id or "").strip()
    if not CASE_ID_RE.fullmatch(safe_case_id):
        return None, None
    uploads_root = os.path.abspath(UPLOADS)
    sidecar_path = os.path.abspath(os.path.join(uploads_root, f"{safe_case_id}.{sidecar_name}.json"))
    if os.path.commonpath([uploads_root, sidecar_path]) != uploads_root:
        return None, None
    return safe_case_id, sidecar_path


def set_case_parse_status(case_id, status, message="", records=0):
    safe_case_id, status_path = resolve_case_sidecar_path(case_id, "status")
    if not safe_case_id:
        return
    state = {
        "status": status,
        "message": message,
        "records": int(records),
        "updated": time.time(),
    }
    with CASE_STATE_LOCK:
        CASE_PARSE_STATUS[safe_case_id] = state
    try:
        with open(status_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
    except Exception:
        pass


def get_case_parse_status(case_id):
    safe_case_id, status_path = resolve_case_sidecar_path(case_id, "status")
    if not safe_case_id:
        return None
    with CASE_STATE_LOCK:
        state = CASE_PARSE_STATUS.get(safe_case_id)
    if state:
        return dict(state)
    if os.path.exists(status_path):
        try:
            with open(status_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                with CASE_STATE_LOCK:
                    CASE_PARSE_STATUS[safe_case_id] = loaded
                return loaded
        except Exception:
            return None
    return None


def set_cached_case_data(case_id, parsed_data):
    safe_case_id, cache_path = resolve_case_sidecar_path(case_id, "parsed")
    if not safe_case_id:
        return
    with CASE_STATE_LOCK:
        CASE_DATA_CACHE[safe_case_id] = parsed_data
    try:
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump(parsed_data, fh, default=str)
    except Exception:
        pass


def get_cached_case_data(case_id):
    safe_case_id, cache_path = resolve_case_sidecar_path(case_id, "parsed")
    if not safe_case_id:
        return None
    with CASE_STATE_LOCK:
        cached = CASE_DATA_CACHE.get(safe_case_id)
    if cached is not None:
        return cached
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            with CASE_STATE_LOCK:
                CASE_DATA_CACHE[safe_case_id] = loaded
            return loaded
        except Exception:
            return None
    return None


def parse_case_background(case_id, file_path, vendor):
    set_case_parse_status(case_id, "parsing", "Parsing uploaded log file...")
    try:
        parsed = parse_uploaded_file(file_path, vendor)
        set_cached_case_data(case_id, parsed)
        set_case_parse_status(case_id, "ready", "Parsing complete.", records=len(parsed))
    except Exception as e:
        set_case_parse_status(case_id, "error", f"{e}", records=0)


def start_case_parse_job(case_id, file_path, vendor):
    set_case_parse_status(case_id, "queued", "Queued for parsing...")
    worker = threading.Thread(target=parse_case_background, args=(case_id, file_path, vendor), daemon=True)
    worker.start()


def render_case_loading_page(case_id, label, vendor):
    safe_label = html.escape(label or "Untitled")
    safe_vendor = html.escape(vendor or "unknown")
    content = f"""
    <section class="panel loading-wrap">
      <h2>Preparing Case: {safe_label} ({safe_vendor})</h2>
      <p id="loadingMessage">Upload successful. Starting parse...</p>
      <div class="progress-track"><div class="progress-fill" id="loadingProgress"></div></div>
      <p class="muted">This page updates automatically and redirects when parsing completes.</p>
      <p><a href="/">Return Home</a></p>
    </section>
    <script>
      (function() {{
        const caseId = "{case_id}";
        const statusEl = document.getElementById("loadingMessage");
        const progressEl = document.getElementById("loadingProgress");
        let synthetic = 10;
        let completed = false;

        function setProgress(value) {{
          const pct = Math.max(0, Math.min(100, value));
          progressEl.style.width = pct.toFixed(0) + "%";
        }}

        function parseStateToMessage(state) {{
          if (state.status === "queued") return "Upload complete. Waiting for parser worker...";
          if (state.status === "parsing") return "Parsing and normalizing records...";
          if (state.status === "ready") return "Parsing complete. Redirecting to case dashboard...";
          if (state.status === "error") return "Parsing failed: " + (state.message || "Unknown error");
          return state.message || "Processing...";
        }}

        function pollStatus() {{
          fetch("/upload_status/" + caseId + "?_=" + Date.now(), {{ cache: "no-store" }})
            .then((res) => res.json())
            .then((state) => {{
              if (completed) return;
              statusEl.textContent = parseStateToMessage(state);
              if (state.status === "ready") {{
                setProgress(100);
                completed = true;
                setTimeout(() => {{
                  window.location.assign(state.next_url || ("/case/" + caseId));
                }}, 350);
                return;
              }}
              if (state.status === "error") {{
                completed = true;
                setProgress(100);
                return;
              }}
              synthetic = Math.min(92, synthetic + Math.random() * 8);
              setProgress(synthetic);
            }})
            .catch(() => {{
              if (completed) return;
              synthetic = Math.min(90, synthetic + 3);
              setProgress(synthetic);
              statusEl.textContent = "Waiting for parser status...";
            }});
        }}

        setProgress(synthetic);
        pollStatus();
        setInterval(pollStatus, 1200);
      }})();
    </script>
    """
    return render_page("Parsing Upload", "Case Loading", content)

def store_case(case_id, label, vendor, path):
    with driver.session() as session:
        session.run(
            """
            CREATE (c:Case {
                sid: $sid,
                label: $label,
                vendor: $vendor,
                path: $path,
                created: timestamp()
            })
            """,
            sid=case_id, label=label, vendor=vendor, path=path
        )

def get_all_cases():
    with driver.session() as session:
        result = session.run(
            """
            MATCH (c:Case)
            RETURN c.sid AS sid, c.label AS label, c.vendor AS vendor
            ORDER BY c.created DESC
            """
        )
        return result.data()

def get_case_by_sid(case_id):
    with driver.session() as session:
        record = session.run(
            "MATCH (c:Case {sid: $sid}) RETURN c LIMIT 1", sid=case_id
        ).single()
        return record["c"] if record else None

def is_tgz_path(file_path):
    name = os.path.basename(str(file_path or "")).lower()
    return name.endswith(".tgz") or name.endswith(".tar.gz")


def extract_tgz_members_safely(archive_path, extract_root):
    extract_root_abs = os.path.abspath(extract_root)
    extracted_files = []
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            member_name = str(member.name or "").strip()
            if not member_name:
                continue
            if member.isdir() or member.issym() or member.islnk():
                continue
            target_path = os.path.abspath(os.path.join(extract_root_abs, member_name))
            if os.path.commonpath([extract_root_abs, target_path]) != extract_root_abs:
                continue

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            source_fh = tar.extractfile(member)
            if source_fh is None:
                continue
            with source_fh:
                with open(target_path, "wb") as dest_fh:
                    shutil.copyfileobj(source_fh, dest_fh)
            extracted_files.append(target_path)
    return extracted_files


def parse_tgz_archive(archive_path, vendor):
    all_records = []
    errors = []
    with tempfile.TemporaryDirectory(prefix="eflp_tgz_", dir=UPLOADS) as extract_root:
        extracted_files = extract_tgz_members_safely(archive_path, extract_root)
        candidates = []
        for path in extracted_files:
            base_name = os.path.basename(path)
            lower_name = base_name.lower()
            if base_name.startswith("."):
                continue
            if is_tgz_path(lower_name):
                continue
            ext = os.path.splitext(lower_name)[1]
            if ext in ARCHIVE_PARSEABLE_EXTENSIONS or ext == "":
                candidates.append(path)

        if not candidates:
            raise Exception("No parseable files found in archive. Supported types: .log, .txt, .csv, .tsv")

        for candidate in sorted(candidates):
            try:
                parsed_rows = parse_uploaded_file(candidate, vendor)
                if parsed_rows:
                    all_records.extend(parsed_rows)
            except Exception as exc:
                errors.append(f"{os.path.basename(candidate)}: {exc}")

    if all_records:
        return all_records
    if errors:
        raise Exception("Unable to parse files from archive: " + "; ".join(errors[:5]))
    raise Exception("Archive parsed successfully but no records were produced.")


def parse_uploaded_file(file_path, vendor):
    if is_tgz_path(file_path):
        return parse_tgz_archive(file_path, vendor)

    ext = os.path.splitext(file_path)[1].lower()
    if ext in [".csv", ".tsv"]:
        sep = "," if ext == ".csv" else "\t"
        try:
            df = pd.read_csv(file_path, sep=sep, dtype=str, keep_default_na=False)
            return df.to_dict("records")
        except Exception as e:
            raise Exception(f"Error parsing CSV/TSV file: {e}")
    else:
        parser_cls = PARSERS.get(vendor)
        if not parser_cls:
            raise Exception(f"Unknown vendor: {vendor}")
        parser = parser_cls()
        return parser.parse(file_path)

def load_case_data(case_id):
    case = get_case_by_sid(case_id)
    if not case:
        return None, "Case not found."
    cached = get_cached_case_data(case_id)
    if cached is not None:
        return case, cached
    vendor = case["vendor"]
    file_path = case["path"]
    try:
        parsed_data = parse_uploaded_file(file_path, vendor)
        set_cached_case_data(case_id, parsed_data)
    except Exception as e:
        return None, f"Error parsing file: {e}"
    return case, parsed_data

def generate_logs_table(df, columns=None):
    preferred = [
        "timestamp", "severity", "log_category", "event", "action", "outcome",
        "user", "rule", "signature", "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "network_type", "message"
    ]
    if columns is None:
        columns = [c for c in preferred if c in df.columns]
        if not columns:
            columns = list(df.columns[:10])
    columns = [str(c) for c in columns]
    for col in columns:
        if col not in df.columns:
            df[col] = ""
    records = df[columns].fillna("").astype(str).to_dict("records")
    column_map = {col: idx for idx, col in enumerate(columns)}
    primary_col = "severity" if "severity" in column_map else ("timestamp" if "timestamp" in column_map else columns[0])
    primary_idx = column_map.get(primary_col, 0)
    primary_dir = "asc" if primary_col == "severity" else "desc"
    secondary_idx = column_map.get("timestamp", "")
    secondary_dir = "desc"

    head = "<tr>" + "".join(f"<th>{html.escape(col)}</th>" for col in columns) + "</tr>"
    row_chunks = []
    for rec in records:
        cells = []
        for col in columns:
            value = html.escape(str(rec.get(col, "")))
            if col == "severity":
                sort_rank = SEVERITY_SORT.get(str(rec.get(col, "")).strip().upper(), 99)
                cells.append(f"<td data-order='{sort_rank}'>{value}</td>")
            else:
                cells.append(f"<td>{value}</td>")
        row_chunks.append("<tr>" + "".join(cells) + "</tr>")
    rows = "".join(row_chunks)

    table = (
        f"<table id='logsTable' data-order-col='{primary_idx}' data-order-dir='{primary_dir}' "
        f"data-order-secondary-col='{secondary_idx}' data-order-secondary-dir='{secondary_dir}'>"
        f"<thead>{head}</thead><tbody>{rows}</tbody></table>"
    )
    return table, column_map

def build_case_export_target(vendor, case_id):
    safe_vendor = re.sub(r"[^a-z0-9]+", "_", str(vendor or "logs").lower()).strip("_") or "logs"
    safe_case = re.sub(r"[^a-z0-9]+", "_", str(case_id or "case").lower()).strip("_") or "case"
    return f"{safe_vendor}_{safe_case[:16]}_logs"


def normalized_records_for_case(case, parsed_data):
    df = pd.DataFrame(parsed_data)
    if df.empty:
        return []
    norm_df = normalize_case_dataframe(df).drop(columns=["timestamp_dt"], errors="ignore")
    norm_df["case_id"] = case.get("sid", "")
    norm_df["case_label"] = case.get("label", "")
    return norm_df.fillna("").to_dict("records")


def generate_export_forms(case_id, vendor):
    default_target = build_case_export_target(vendor, case_id)
    safe_case_id = html.escape(str(case_id))
    safe_target = html.escape(default_target)
    es_form = f"""
    <form action="/export" method="post" style="margin-bottom:15px;">
      <input type="hidden" name="case_id" value="{safe_case_id}" />
      <label>Elasticsearch URL:</label>
      <input type="text" name="es_url" value="http://localhost:9200" />
      <label>Index:</label>
      <input type="text" name="es_index" value="{safe_target}" />
      <label>ES Username:</label>
      <input type="text" name="es_user" />
      <label>ES Password:</label>
      <input type="password" name="es_pass" />
      <input class="button" type="submit" value="Export to Elasticsearch" />
    </form>
    """
    influx_form = f"""
    <form action="/export_influx" method="post" style="margin-bottom:15px;">
      <input type="hidden" name="case_id" value="{safe_case_id}" />
      <label>InfluxDB URL:</label>
      <input type="text" name="influxdb_url" value="http://localhost:8086" />
      <label>Database:</label>
      <input type="text" name="influxdb_db" value="{safe_target}" />
      <label>InfluxDB Username:</label>
      <input type="text" name="influxdb_user" />
      <label>InfluxDB Password:</label>
      <input type="password" name="influxdb_pass" />
      <input class="button" type="submit" value="Export to InfluxDB" />
    </form>
    """
    csv_form = f"""
    <form action="/export_csv" method="post" style="margin-bottom:15px;">
      <input type="hidden" name="case_id" value="{safe_case_id}" />
      <input class="button" type="submit" value="Export to CSV" />
    </form>
    """
    json_form = f"""
    <form action="/export_json" method="post" style="margin-bottom:15px;">
      <input type="hidden" name="case_id" value="{safe_case_id}" />
      <input class="button secondary" type="submit" value="Export to JSON" />
    </form>
    """
    return es_form + influx_form + csv_form + json_form

def generate_export_panel(case_id, vendor):
    export_forms = generate_export_forms(case_id, vendor)
    return f"""
      <div class="panel">
        <h3>Export Pipelines</h3>
        {export_forms}
      </div>
    """

def export_to_influxdb(parsed_data, vendor, influxdb_url, influxdb_db, influxdb_user, influxdb_pass, case_id="", case_label=""):
    parsed_url = urlparse(influxdb_url)
    host = parsed_url.hostname if parsed_url.hostname else influxdb_url
    port = parsed_url.port if parsed_url.port else 8086
    client = InfluxDBClient(host=host, port=port, username=influxdb_user, password=influxdb_pass, database=influxdb_db)
    client.create_database(influxdb_db)
    points = []
    for rec in parsed_data:
        ts = rec.get("timestamp")
        try:
            dt = date_parser.parse(ts)
            iso_time = dt.isoformat()
        except Exception:
            iso_time = ts
        point = {
            "measurement": "logs",
            "tags": {
                "vendor": vendor,
                "case_id": str(case_id or rec.get("case_id", "")),
                "case_label": str(case_label or rec.get("case_label", "")),
                "severity": rec.get("severity", ""),
                "log_category": rec.get("log_category", rec.get("subtype", "")),
                "action": rec.get("action", ""),
                "outcome": rec.get("outcome", ""),
            },
            "time": iso_time,
            "fields": {
                "message": rec.get("message", ""),
                "record_id": rec.get("record_id", ""),
                "event_id": rec.get("event_id", ""),
                "event": rec.get("event", ""),
                "user": rec.get("user", ""),
                "rule": rec.get("rule", "")
            }
        }
        points.append(point)
    client.write_points(points)

def severity_from_priority_value(value) -> str:
    try:
        priority = int(str(value).strip())
    except Exception:
        return "INFO"
    sev_code = priority % 8
    if sev_code <= 2:
        return "CRITICAL"
    if sev_code == 3:
        return "HIGH"
    if sev_code == 4:
        return "MEDIUM"
    if sev_code == 5:
        return "LOW"
    return "INFO"


def canonicalize_severity_value(value) -> str:
    text = str(value or "").strip()
    if not text:
        return "INFO"
    upper = text.upper()
    if upper in SEVERITY_SORT:
        return upper
    if upper in SEVERITY_ALIAS_MAP:
        return SEVERITY_ALIAS_MAP[upper]
    if re.fullmatch(r"\d+", text):
        return severity_from_priority_value(text)
    token = normalize_token_text(text).upper().replace(" ", "_")
    if token in SEVERITY_ALIAS_MAP:
        return SEVERITY_ALIAS_MAP[token]
    return "INFO"


def canonicalize_protocol_value(value) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    token = normalize_token_text(text).upper().replace(" ", "")
    if not token or token in {"UNKNOWN", "UNSET", "NA"}:
        return ""
    if token in PROTOCOL_ALIAS_MAP:
        return PROTOCOL_ALIAS_MAP[token]
    if token.isdigit() and token in PROTOCOL_ALIAS_MAP:
        return PROTOCOL_ALIAS_MAP[token]
    return token[:16]


def normalize_ip_value(value) -> str:
    text = str(value or "").strip().strip('"').strip("'").strip(",;()")
    if not text:
        return ""
    if normalize_token_text(text) in UNKNOWN_VALUE_TOKENS:
        return ""

    candidate = text
    if candidate.startswith("[") and "]" in candidate:
        close_idx = candidate.find("]")
        bracket_ip = candidate[1:close_idx]
        tail = candidate[close_idx + 1:]
        if not tail or (tail.startswith(":") and tail[1:].isdigit()):
            candidate = bracket_ip

    if candidate.lower().startswith("::ffff:"):
        candidate = candidate[7:]

    if ":" in candidate and candidate.count(":") == 1:
        left, right = candidate.rsplit(":", 1)
        if IPV4_TEXT_REGEX.fullmatch(left) and right.isdigit():
            candidate = left

    candidate = candidate.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass

    match = IPV4_TEXT_REGEX.search(candidate)
    return match.group(0) if match else ""


def canonicalize_port_value(value):
    text = str(value or "").strip()
    if not text:
        return None
    if ":" in text and text.count(":") == 1:
        left, right = text.rsplit(":", 1)
        if IPV4_TEXT_REGEX.fullmatch(left) and right.isdigit():
            text = right
    if "/" in text:
        tail = text.rsplit("/", 1)[-1]
        if tail.isdigit():
            text = tail
    if not re.fullmatch(r"\d+", text):
        return None
    port = int(text)
    if 0 <= port <= 65535:
        return port
    return None


def extract_message_ips(text):
    payload = str(text or "")
    src_match = re.search(r"\b(?:src|source|client|from)\s*(?:=|:|->|\s)\s*((?:\d{1,3}\.){3}\d{1,3})\b", payload, re.IGNORECASE)
    dst_match = re.search(r"\b(?:dst|dest|destination|server|to)\s*(?:=|:|->|\s)\s*((?:\d{1,3}\.){3}\d{1,3})\b", payload, re.IGNORECASE)

    src_ip = normalize_ip_value(src_match.group(1)) if src_match else ""
    dst_ip = normalize_ip_value(dst_match.group(1)) if dst_match else ""
    if src_ip or dst_ip:
        return src_ip, dst_ip

    ips = IPV4_TEXT_REGEX.findall(payload)
    if not ips:
        return "", ""
    if len(ips) == 1:
        return normalize_ip_value(ips[0]), ""
    return normalize_ip_value(ips[0]), normalize_ip_value(ips[1])


def timestamp_has_explicit_year(value) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if re.search(r"(?<!\d)\d{4}(?!\d)", text):
        return True
    return bool(re.search(r"\b\d{1,4}[/-]\d{1,2}[/-]\d{1,4}\b", text))


def roll_back_one_year(ts: pd.Timestamp) -> pd.Timestamp:
    dt = ts.to_pydatetime()
    try:
        shifted = dt.replace(year=dt.year - 1)
    except ValueError:
        shifted = dt.replace(year=dt.year - 1, month=2, day=28)
    adjusted = pd.Timestamp(shifted)
    if adjusted.tzinfo is None:
        return adjusted.tz_localize("UTC")
    return adjusted.tz_convert("UTC")


def adjust_missing_year_future_timestamp(parsed_ts: pd.Timestamp, raw_text: str) -> pd.Timestamp:
    if pd.isna(parsed_ts):
        return parsed_ts
    if timestamp_has_explicit_year(raw_text):
        return parsed_ts
    future_threshold = pd.Timestamp.now(tz="UTC") + pd.Timedelta(days=2)
    adjusted = parsed_ts
    for _ in range(3):
        if adjusted <= future_threshold:
            break
        adjusted = roll_back_one_year(adjusted)
    return adjusted


def normalize_timestamp_value(value):
    if value is None:
        return pd.NaT
    text = str(value).strip()
    if not text:
        return pd.NaT
    cleaned = normalize_token_text(text)
    if cleaned in UNKNOWN_VALUE_TOKENS:
        return pd.NaT

    numeric_match = re.fullmatch(r"-?\d+(?:\.\d+)?", text)
    if numeric_match:
        integral = text.lstrip("-").split(".", 1)[0]
        if len(integral) >= 10:
            try:
                num = float(text)
                if len(integral) >= 18:
                    return pd.to_datetime(num, unit="ns", utc=True, errors="coerce")
                if len(integral) >= 15:
                    return pd.to_datetime(num, unit="us", utc=True, errors="coerce")
                if len(integral) >= 12:
                    return pd.to_datetime(num, unit="ms", utc=True, errors="coerce")
                return pd.to_datetime(num, unit="s", utc=True, errors="coerce")
            except Exception:
                pass

    parsed = pd.to_datetime(text, errors="coerce", utc=True)
    return adjust_missing_year_future_timestamp(parsed, text)


def ensure_network_type(df: pd.DataFrame) -> pd.DataFrame:
    nts = []
    for _, row in df.iterrows():
        if str(row.get("network_type", "")).strip():
            nts.append(str(row.get("network_type", "")).strip())
            continue
        s = " ".join(str(x) for x in [
            row.get("message", ""),
            row.get("severity", ""),
            row.get("subtype", ""),
            row.get("object", ""),
            row.get("log_category", ""),
            row.get("protocol", ""),
        ]).lower()
        t = "unknown"
        if any(k in s for k in ["sslvpn", "nsvpn", "vpn", "citrix gateway", "globalprotect", "wireguard", "openvpn"]):
            t = "sslvpn"
        elif any(k in s for k in ["ike", "ipsec", "l2tp", "pptp"]):
            t = "ike"
        elif "appfw" in s or "app firewall" in s:
            t = "appfw"
        elif "wan" in s or "internet" in s:
            t = "wan"
        elif "lan" in s or "intranet" in s:
            t = "lan"
        elif "dmz" in s:
            t = "dmz"
        nts.append(t)
    df["network_type"] = nts
    return df

def coalesce_columns(df: pd.DataFrame, candidates, default=""):
    existing = [c for c in candidates if c in df.columns]
    if not existing:
        return pd.Series([default] * len(df), index=df.index, dtype=object)
    result = df[existing[0]].fillna("").astype(str)
    for col in existing[1:]:
        candidate = df[col].fillna("").astype(str)
        mask = result.str.strip().eq("")
        result = result.where(~mask, candidate)
    return result

def normalize_token_text(value: str) -> str:
    lowered = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9]+", " ", lowered).strip()

def canonicalize_log_category_value(value: str) -> str:
    text = normalize_token_text(value)
    if not text or text in UNKNOWN_VALUE_TOKENS:
        return ""
    token = text.replace(" ", "_")
    if token in CANONICAL_LOG_CATEGORIES:
        return token
    if token in LOG_CATEGORY_ALIASES:
        return LOG_CATEGORY_ALIASES[token]
    inferred = infer_log_category_from_text(text)
    return "" if inferred == "unknown" else inferred

def canonicalize_outcome_value(value: str) -> str:
    text = normalize_token_text(value)
    if not text or text in UNKNOWN_VALUE_TOKENS:
        return ""
    token = text.replace(" ", "_")
    if token in CANONICAL_OUTCOMES:
        return token
    if token in OUTCOME_ALIASES:
        return OUTCOME_ALIASES[token]
    inferred = infer_outcome_from_text(text)
    return "" if inferred == "unknown" else inferred

def infer_log_category_from_text(text: str) -> str:
    s = str(text or "").lower()
    if any(k in s for k in ["threat", "intrusion", "ips", "ids", "attack", "exploit", "signature", "idp", "utm", "appfw", "waf"]):
        return "threat"
    if any(k in s for k in ["malware", "virus", "spyware", "ransomware", "botnet", "trojan", "c2"]):
        return "malware"
    if any(k in s for k in ["auth", "login", "logout", "radius", "ldap", "saml", "mfa", "aaa", "user-id"]):
        return "authentication"
    if any(k in s for k in ["vpn", "ipsec", "ike", "sslvpn", "nsvpn", "globalprotect", "tunnel"]):
        return "vpn"
    if any(k in s for k in ["config", "policy install", "commit", "admin", "change", "audit", "cmd", "cli"]):
        return "configuration"
    if any(k in s for k in ["system", "daemon", "kernel", "cpu", "memory", "fan", "health", "chassis", "resource"]):
        return "system"
    if any(k in s for k in ["dns", "domain", "resolver", "query", "dnssec"]):
        return "dns"
    if any(k in s for k in ["url", "web", "http", "https", "proxy"]):
        return "web"
    if any(k in s for k in ["ha", "cluster", "failover", "sync", "heartbeat"]):
        return "ha"
    if any(k in s for k in ["route", "bgp", "ospf", "rip", "routing"]):
        return "routing"
    if any(k in s for k in ["wireless", "wifi", "ssid", "wlan", "ap "]):
        return "wireless"
    if any(k in s for k in ["nat", "session", "flow", "traffic", "connection", "firewall", "packet", "rt_flow"]):
        return "traffic"
    return "unknown"

def infer_outcome_from_text(text: str) -> str:
    s = str(text or "").lower()
    if any(k in s for k in ["deny", "denied", "drop", "blocked", "reject", "quarantine", "reset"]):
        return "blocked"
    if any(k in s for k in ["fail", "failed", "error", "invalid", "timeout"]):
        return "failed"
    if any(k in s for k in ["allow", "accept", "permit", "pass", "session create"]):
        return "allowed"
    if any(k in s for k in ["success", "successful", "authenticated", "ok"]):
        return "success"
    if any(k in s for k in ["detect", "detected", "alert", "threat"]):
        return "detected"
    return "unknown"

def normalize_case_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    norm = df.copy()
    norm["timestamp"] = coalesce_columns(norm, ["timestamp", "@timestamp", "time", "event_time", "generated_time", "eventtime", "receive_time"])
    norm["severity"] = coalesce_columns(norm, ["severity", "level", "priority", "pri"], default="INFO")
    norm["event"] = coalesce_columns(norm, ["event", "event_type", "subtype", "log_type", "signature"])
    norm["action"] = coalesce_columns(norm, ["action", "palo_action", "result", "status", "disposition"])
    norm["outcome"] = coalesce_columns(norm, ["outcome", "status", "result", "disposition"])
    norm["log_category"] = coalesce_columns(norm, ["log_category", "category", "type", "subtype", "event_type", "module", "service"])
    norm["user"] = coalesce_columns(norm, ["user", "username", "src_user", "srcuser", "account", "userid"])
    norm["rule"] = coalesce_columns(norm, ["rule", "policy", "policyid", "policyname", "acl"])
    norm["signature"] = coalesce_columns(norm, ["signature", "threat", "attack", "virusname"])
    norm["src_ip"] = coalesce_columns(norm, ["src_ip", "srcip", "source_ip", "source", "src", "client_ip", "clientip"])
    norm["dst_ip"] = coalesce_columns(norm, ["dst_ip", "dstip", "destination_ip", "destination", "dst", "serverip"])
    norm["src_port"] = coalesce_columns(norm, ["src_port", "srcport", "sport", "spt"])
    norm["dst_port"] = coalesce_columns(norm, ["dst_port", "dstport", "dport", "dpt"])
    norm["protocol"] = coalesce_columns(norm, ["protocol", "proto", "service", "transport"])
    norm["message"] = coalesce_columns(norm, ["message", "msg", "description"])
    norm["event_id"] = coalesce_columns(norm, ["event_id", "eventid", "logid", "id", "msgid"])
    norm["session_id"] = coalesce_columns(norm, ["session_id", "sessionid", "sid", "connid", "flowid"])

    norm["severity"] = norm["severity"].fillna("").astype(str).map(canonicalize_severity_value)

    norm["action"] = norm["action"].fillna("").astype(str)
    norm["action"] = norm["action"].map(lambda x: normalize_token_text(x).replace(" ", "_"))
    missing_action = norm["action"].eq("")
    if missing_action.any():
        action_seed = norm["message"].fillna("").astype(str).str.lower()
        norm.loc[missing_action & action_seed.str.contains(r"\b(deny|drop|block|reject|quarantine)\b", regex=True), "action"] = "deny"
        norm.loc[missing_action & action_seed.str.contains(r"\b(allow|accept|permit|pass)\b", regex=True), "action"] = "allow"
        norm.loc[missing_action & action_seed.str.contains(r"\b(login|logon)\b", regex=True), "action"] = "login"
        norm.loc[missing_action & action_seed.str.contains(r"\blogout\b", regex=True), "action"] = "logout"
        norm.loc[missing_action & action_seed.str.contains(r"\b(reset|teardown|close)\b", regex=True), "action"] = "close"

    norm["event"] = norm["event"].fillna("").astype(str).str.strip()
    missing_event = norm["event"].eq("")
    if missing_event.any():
        inferred_event = norm["message"].fillna("").astype(str).str.extract(r"\b([A-Z][A-Z0-9_]{3,})\b", expand=False).fillna("")
        norm.loc[missing_event, "event"] = inferred_event[missing_event]
    norm.loc[norm["event"].str.strip().eq(""), "event"] = "unknown"

    norm["protocol"] = norm["protocol"].fillna("").astype(str).map(canonicalize_protocol_value)
    missing_protocol = norm["protocol"].eq("")
    if missing_protocol.any():
        protocol_seed = norm["message"].fillna("").astype(str).str.lower()
        norm.loc[missing_protocol & protocol_seed.str.contains(r"\btcp\b", regex=True), "protocol"] = "TCP"
        norm.loc[missing_protocol & protocol_seed.str.contains(r"\budp\b", regex=True), "protocol"] = "UDP"
        norm.loc[missing_protocol & protocol_seed.str.contains(r"\bicmpv?6?\b", regex=True), "protocol"] = "ICMP"
        norm.loc[missing_protocol & protocol_seed.str.contains(r"\besp\b", regex=True), "protocol"] = "ESP"
        norm.loc[missing_protocol & protocol_seed.str.contains(r"\bgre\b", regex=True), "protocol"] = "GRE"
    norm.loc[norm["protocol"].eq(""), "protocol"] = "UNKNOWN"

    norm["src_ip"] = norm["src_ip"].fillna("").astype(str).map(normalize_ip_value)
    norm["dst_ip"] = norm["dst_ip"].fillna("").astype(str).map(normalize_ip_value)
    missing_src = norm["src_ip"].eq("")
    missing_dst = norm["dst_ip"].eq("")
    if missing_src.any() or missing_dst.any():
        ip_pairs = norm["message"].fillna("").astype(str).map(extract_message_ips)
        msg_src = ip_pairs.map(lambda pair: pair[0])
        msg_dst = ip_pairs.map(lambda pair: pair[1])
        norm.loc[missing_src, "src_ip"] = msg_src[missing_src]
        norm.loc[missing_dst, "dst_ip"] = msg_dst[missing_dst]

    norm["src_port"] = norm["src_port"].map(canonicalize_port_value)
    norm["dst_port"] = norm["dst_port"].map(canonicalize_port_value)
    src_port_from_msg = norm["message"].fillna("").astype(str).str.extract(r"\b(?:spt|sport|srcport|source_port|src[\s_]?port)\s*[=:]\s*(\d{1,5})\b", expand=False)
    dst_port_from_msg = norm["message"].fillna("").astype(str).str.extract(r"\b(?:dpt|dport|dstport|destination_port|dst[\s_]?port)\s*[=:]\s*(\d{1,5})\b", expand=False)
    missing_src_port = norm["src_port"].isna()
    missing_dst_port = norm["dst_port"].isna()
    if missing_src_port.any():
        norm.loc[missing_src_port, "src_port"] = src_port_from_msg[missing_src_port].map(canonicalize_port_value)
    if missing_dst_port.any():
        norm.loc[missing_dst_port, "dst_port"] = dst_port_from_msg[missing_dst_port].map(canonicalize_port_value)

    norm["log_category"] = norm["log_category"].fillna("").astype(str).map(canonicalize_log_category_value)
    missing_category = norm["log_category"].eq("")
    if missing_category.any():
        category_seed = (
            coalesce_columns(norm, ["category", "type", "subtype"]).fillna("").astype(str) + " " +
            norm["message"].fillna("").astype(str) + " " +
            norm["event"].fillna("").astype(str) + " " +
            norm["action"].fillna("").astype(str) + " " +
            norm["protocol"].fillna("").astype(str)
        )
        norm.loc[missing_category, "log_category"] = category_seed[missing_category].map(infer_log_category_from_text)
    norm["log_category"] = norm["log_category"].fillna("").astype(str).map(canonicalize_log_category_value)
    norm.loc[norm["log_category"].eq(""), "log_category"] = "unknown"

    norm["outcome"] = norm["outcome"].fillna("").astype(str).map(canonicalize_outcome_value)
    missing_outcome = norm["outcome"].eq("")
    if missing_outcome.any():
        outcome_seed = (
            norm["action"].fillna("").astype(str) + " " +
            norm["event"].fillna("").astype(str) + " " +
            norm["message"].fillna("").astype(str)
        )
        norm.loc[missing_outcome, "outcome"] = outcome_seed[missing_outcome].map(infer_outcome_from_text)
    norm["outcome"] = norm["outcome"].fillna("").astype(str).map(canonicalize_outcome_value)
    norm.loc[norm["outcome"].eq(""), "outcome"] = "unknown"

    raw_timestamp = norm["timestamp"].fillna("").astype(str)
    norm["timestamp_dt"] = raw_timestamp.map(normalize_timestamp_value)
    rendered_timestamp = norm["timestamp_dt"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    norm["timestamp"] = rendered_timestamp.where(norm["timestamp_dt"].notna(), raw_timestamp.str.strip()).fillna("")

    norm = ensure_network_type(norm)

    return norm

@app.route("/")
def index():
    cases = get_all_cases()
    case_box = "<div class='case-box'><h3>All Cases</h3>"
    if cases:
        for c in cases:
            case_box += f"<p><a href='/case/{c['sid']}'>{c['label']} ({c['vendor']})</a></p>"
    else:
        case_box += "<p>No cases found.</p>"
    case_box += "</div>"
    upload_form = """
    <div class='panel'>
      <h2>Upload Logs</h2>
      <p style="margin-top:0;color:#86b9a8;">Upload a vendor dump (`.log`, `.txt`, `.csv`, `.tsv`, `.tgz`) and EFLP will normalize traffic, authentication, VPN, threat, system, and configuration events for forensic triage.</p>
      <form action="/upload" method="post" enctype="multipart/form-data">
        <label>Case Label:</label>
        <input type="text" name="label" placeholder="Case label" />
        <label>Vendor:</label>
        <select name="vendor">
            <option value="palo_alto">Palo Alto</option>
            <option value="fortigate">Fortigate</option>
            <option value="sonicwall">SonicWall</option>
            <option value="cisco_ftd">Cisco FTD</option>
            <option value="checkpoint">Check Point</option>
            <option value="meraki">Meraki</option>
            <option value="unifi">Unifi</option>
            <option value="juniper">Juniper</option>
            <option value="watchguard">WatchGuard</option>
            <option value="sophos_utm">Sophos UTM</option>
            <option value="sophos_xgs">Sophos XGS</option>
            <option value="netscaler">Netscaler (Citrix ADC)</option>
        </select>
        <label>Log File:</label>
        <input type="file" name="logfile" accept=".log,.txt,.csv,.tsv,.tgz,.tar.gz" />
        <input class="button" type="submit" value="Upload" />
      </form>
    </div>
    """
    content = case_box + upload_form
    return render_page("EFLP", "EFLP v0.1.3", content)

@app.route("/upload", methods=["POST"])
def upload():
    label = request.form.get("label", "Untitled")
    vendor = request.form.get("vendor")
    uploaded_file = request.files.get("logfile")
    if not uploaded_file or uploaded_file.filename == "":
        return "No file selected"
    if vendor not in PARSERS:
        return render_page("Error", "Error", f"Unsupported vendor '{html.escape(str(vendor))}'.")

    case_id = str(uuid.uuid4())
    safe_name = secure_filename(uploaded_file.filename)
    if not safe_name:
        return render_page("Error", "Error", "Invalid filename.")
    file_path = os.path.join(UPLOADS, f"{case_id}_{safe_name}")
    uploaded_file.save(file_path)
    store_case(case_id, label, vendor, file_path)
    start_case_parse_job(case_id, file_path, vendor)
    return render_case_loading_page(case_id, label, vendor)


@app.route("/upload_status/<case_id>")
def upload_status(case_id):
    case = get_case_by_sid(case_id)
    if not case:
        return jsonify({"status": "error", "message": "Case not found.", "next_url": "/"}), 404

    cached = get_cached_case_data(case_id)
    if cached is not None:
        return jsonify({"status": "ready", "records": len(cached), "next_url": f"/case/{case_id}"})

    state = get_case_parse_status(case_id)
    if state:
        payload = {
            "status": state.get("status", "queued"),
            "message": state.get("message", ""),
            "records": int(state.get("records", 0)),
            "next_url": f"/case/{case_id}",
        }
        return jsonify(payload)

    return jsonify({"status": "queued", "message": "Waiting for parser...", "records": 0, "next_url": f"/case/{case_id}"})

@app.route("/case/<case_id>")
def view_case(case_id):
    case_meta = get_case_by_sid(case_id)
    if not case_meta:
        return render_page("Error", "Error", "Case not found.")

    cached = get_cached_case_data(case_id)
    parse_state = get_case_parse_status(case_id)
    if cached is None and parse_state and parse_state.get("status") in {"queued", "parsing"}:
        return render_case_loading_page(case_id, case_meta.get("label", "Untitled"), case_meta.get("vendor", "unknown"))
    if parse_state and parse_state.get("status") == "error":
        message = html.escape(parse_state.get("message", "Parsing failed."))
        return render_page("Error", "Error", f"Error parsing file: {message}")

    case, result = load_case_data(case_id)
    if not case:
        return render_page("Error", "Error", result)
    vendor = case["vendor"]
    label = case["label"]
    df = pd.DataFrame(result)

    if df.empty:
        export_panel = generate_export_panel(case_id, vendor)
        empty_content = f"""
          <h2>Case: {label} ({vendor})</h2>
          <p>No records parsed.</p>
          {export_panel}
          <br><a href="/">Back</a>
        """
        return render_page(label, f"Case: {label} ({vendor})", empty_content)

    df = normalize_case_dataframe(df)

    chart_blocks = []
    plotly_loaded = False

    def fig_to_html(fig):
        nonlocal plotly_loaded
        include = "cdn" if not plotly_loaded else False
        plotly_loaded = True
        return fig.to_html(full_html=False, include_plotlyjs=include)

    def scale_bar_figure(fig, tick_angle=0):
        bottom_margin = 70 if tick_angle == 0 else 130
        fig.update_layout(
            template="plotly_dark",
            margin={"l": 64, "r": 18, "t": 64, "b": bottom_margin},
            yaxis={"rangemode": "tozero", "automargin": True},
            xaxis={"tickangle": tick_angle, "automargin": True},
        )

    def scale_pie_figure(fig):
        fig.update_layout(template="plotly_dark", margin={"l": 28, "r": 28, "t": 64, "b": 20})

    def scale_area_figure(fig):
        fig.update_layout(
            template="plotly_dark",
            margin={"l": 64, "r": 20, "t": 64, "b": 72},
            yaxis={"rangemode": "tozero", "automargin": True},
            xaxis={"automargin": True},
        )

    def add_chart(title, fig, filter_column="", filter_source="auto"):
        rendered = fig_to_html(fig)
        match = PLOTLY_DIV_ID_RE.search(rendered)
        chart_blocks.append({
            "title": title,
            "html": rendered,
            "plotly_id": match.group(1) if match else "",
            "filter_column": filter_column,
            "filter_source": filter_source,
        })

    severity_counts = df["severity"].fillna("INFO").astype(str).str.upper().value_counts()
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if not severity_counts.empty:
        ordered_index = [s for s in severity_order if s in severity_counts.index] + [s for s in severity_counts.index if s not in severity_order]
        severity_counts = severity_counts.reindex(ordered_index)
        fig_severity = px.bar(
            x=severity_counts.index, y=severity_counts.values,
            color=severity_counts.index,
            color_discrete_map={
                "CRITICAL": "#dc2626",
                "HIGH": "#ea580c",
                "MEDIUM": "#ca8a04",
                "LOW": "#16a34a",
                "INFO": "#0891b2",
            },
            labels={"x": "Severity", "y": "Count"},
            title=f"{label} - Severity Distribution",
        )
        fig_severity.update_layout(showlegend=False)
        fig_severity.update_traces(text=severity_counts.values, textposition="outside", cliponaxis=False)
        scale_bar_figure(fig_severity, tick_angle=0)
        add_chart("Severity Distribution", fig_severity, filter_column="severity", filter_source="x")

    category_counts = df["log_category"].fillna("unknown").astype(str).replace("", "unknown").value_counts()
    if not category_counts.empty:
        category_order = [c for c in CANONICAL_LOG_CATEGORY_ORDER if c in category_counts.index]
        category_order += [c for c in category_counts.index if c not in CANONICAL_LOG_CATEGORY_ORDER]
        category_counts = category_counts.reindex(category_order)
    if not category_counts.empty:
        fig_category = px.bar(
            x=category_counts.index, y=category_counts.values,
            labels={"x": "Log Category", "y": "Count"},
            title=f"{label} - Forensic Log Category Distribution"
        )
        fig_category.update_traces(text=category_counts.values, textposition="outside", cliponaxis=False)
        scale_bar_figure(fig_category, tick_angle=-35)
        add_chart("Forensic Category Distribution", fig_category, filter_column="log_category", filter_source="x")

    outcome_counts = df["outcome"].fillna("unknown").astype(str).replace("", "unknown").value_counts()
    if not outcome_counts.empty:
        outcome_order = [o for o in CANONICAL_OUTCOME_ORDER if o in outcome_counts.index]
        outcome_order += [o for o in outcome_counts.index if o not in CANONICAL_OUTCOME_ORDER]
        outcome_counts = outcome_counts.reindex(outcome_order)
    if not outcome_counts.empty:
        fig_outcome = px.pie(
            names=outcome_counts.index, values=outcome_counts.values,
            title=f"{label} - Outcome Breakdown", hole=0.35
        )
        scale_pie_figure(fig_outcome)
        add_chart("Outcome Breakdown", fig_outcome, filter_column="outcome", filter_source="label")

    event_series = df["event"].fillna("").astype(str)
    if event_series.str.strip().eq("").all():
        event_series = df["message"].astype(str).str.extract(r'\b([A-Z][A-Z0-9_]{3,})\b', expand=False).fillna("misc")
    event_series = event_series.fillna("").astype(str)
    event_series = event_series.where(event_series.str.strip().ne(""), "unknown")
    event_counts = event_series.value_counts()
    if not event_counts.empty:
        event_dist = event_counts.head(20)
        fig_event_dist = px.bar(
            x=event_dist.index, y=event_dist.values,
            labels={"x": "Event", "y": "Count"},
            title=f"{label} - Event Distribution"
        )
        fig_event_dist.update_traces(text=event_dist.values, textposition="outside", cliponaxis=False)
        scale_bar_figure(fig_event_dist, tick_angle=-35)
        add_chart("Event Distribution", fig_event_dist, filter_column="event", filter_source="x")

    if not event_counts.empty:
        top10 = event_counts.head(10)
        other = event_counts.iloc[10:].sum()
        pie_df = top10.reset_index()
        pie_df.columns = ["event", "count"]
        if other:
            pie_df.loc[len(pie_df)] = ["Other", int(other)]
        fig_events = px.pie(
            pie_df, names="event", values="count",
            title=f"{label} - Most Common Security Events", hole=0.3
        )
        scale_pie_figure(fig_events)
        add_chart("Top Security Events", fig_events, filter_column="event", filter_source="label")

    ip_counts = df["src_ip"].fillna("").astype(str)
    ip_counts = ip_counts[ip_counts.str.strip().ne("")].value_counts().head(20)
    if ip_counts.empty:
        df["ip_for_count"] = df["message"].astype(str).str.extract(r'((?:\d{1,3}\.){3}\d{1,3})', expand=False)
        ip_counts = df["ip_for_count"].fillna("").astype(str)
        ip_counts = ip_counts[ip_counts.str.strip().ne("")].value_counts().head(20)
    if not ip_counts.empty:
        fig_ip = px.bar(
            x=ip_counts.index, y=ip_counts.values,
            labels={"x": "IP Address", "y": "Hits"},
            title=f"{label} - Top {min(20, len(ip_counts))} Source IPs"
        )
        fig_ip.update_traces(text=ip_counts.values, textposition="outside", cliponaxis=False)
        scale_bar_figure(fig_ip, tick_angle=-45)
        add_chart("Top Source IPs", fig_ip, filter_column="src_ip", filter_source="x")

    dst_ip_counts = df["dst_ip"].fillna("").astype(str)
    dst_ip_counts = dst_ip_counts[dst_ip_counts.str.strip().ne("")].value_counts().head(20)
    if not dst_ip_counts.empty:
        fig_dst_ip = px.bar(
            x=dst_ip_counts.index, y=dst_ip_counts.values,
            labels={"x": "Destination IP", "y": "Hits"},
            title=f"{label} - Top {min(20, len(dst_ip_counts))} Destination IPs"
        )
        fig_dst_ip.update_traces(text=dst_ip_counts.values, textposition="outside", cliponaxis=False)
        scale_bar_figure(fig_dst_ip, tick_angle=-45)
        add_chart("Top Destination IPs", fig_dst_ip, filter_column="dst_ip", filter_source="x")

    user_counts = df["user"].fillna("").astype(str)
    user_counts = user_counts[user_counts.str.strip().ne("")].value_counts().head(15)
    if not user_counts.empty:
        fig_users = px.bar(
            x=user_counts.index, y=user_counts.values,
            labels={"x": "User / Account", "y": "Event Count"},
            title=f"{label} - Top User Identities Observed"
        )
        fig_users.update_traces(text=user_counts.values, textposition="outside", cliponaxis=False)
        scale_bar_figure(fig_users, tick_angle=-45)
        add_chart("Top User Identities", fig_users, filter_column="user", filter_source="x")

    auth_df = df[df["log_category"].isin(["authentication", "vpn"])].copy()
    if not auth_df.empty:
        auth_df["outcome"] = auth_df["outcome"].fillna("unknown").replace("", "unknown")
        auth_counts = auth_df.groupby(["log_category", "outcome"]).size().reset_index(name="count")
        fig_auth = px.bar(
            auth_counts, x="outcome", y="count", color="log_category",
            labels={"outcome": "Outcome", "count": "Count", "log_category": "Category"},
            title=f"{label} - Authentication & VPN Outcomes", barmode="group"
        )
        fig_auth.update_traces(cliponaxis=False)
        scale_bar_figure(fig_auth, tick_angle=-15)
        add_chart("Authentication & VPN Outcomes", fig_auth, filter_column="outcome", filter_source="x")

    cfg_df = df[df["log_category"].isin(["configuration", "system", "ha", "routing"])].copy()
    if not cfg_df.empty:
        cfg_events = cfg_df["event"].fillna("unknown").astype(str).replace("", "unknown").value_counts().head(12)
        if not cfg_events.empty:
            fig_cfg = px.bar(
                x=cfg_events.index, y=cfg_events.values,
                labels={"x": "Config/System Event", "y": "Count"},
                title=f"{label} - Configuration & System Change Activity"
            )
            fig_cfg.update_traces(text=cfg_events.values, textposition="outside", cliponaxis=False)
            scale_bar_figure(fig_cfg, tick_angle=-45)
            add_chart("Configuration and System Activity", fig_cfg, filter_column="event", filter_source="x")

    timeline_df = df.dropna(subset=["timestamp_dt"]).copy()
    if not timeline_df.empty:
        timeline_df["hour_bucket"] = timeline_df["timestamp_dt"].dt.floor("h")
        timeline_counts = timeline_df.groupby(["hour_bucket", "log_category"]).size().reset_index(name="count")
        fig_timeline = px.area(
            timeline_counts, x="hour_bucket", y="count", color="log_category",
            labels={"hour_bucket": "Time", "count": "Events", "log_category": "Category"},
            title=f"{label} - Event Timeline by Log Category"
        )
        scale_area_figure(fig_timeline)
        add_chart("Category Timeline", fig_timeline, filter_column="log_category", filter_source="trace")

    nt_counts = df["network_type"].fillna("unknown").astype(str).replace("", "unknown").value_counts()
    if not nt_counts.empty:
        fig_nt = px.bar(
            x=nt_counts.index, y=nt_counts.values,
            labels={"x": "Network Type", "y": "Count"},
            title=f"{label} - Distribution by Network Type"
        )
        fig_nt.update_traces(text=nt_counts.values, textposition="outside", cliponaxis=False)
        scale_bar_figure(fig_nt, tick_angle=-15)
        add_chart("Network Type Distribution", fig_nt, filter_column="network_type", filter_source="x")

    protocol_counts = df["protocol"].fillna("UNKNOWN").astype(str).str.upper().replace("", "UNKNOWN").value_counts().head(12)
    if not protocol_counts.empty:
        fig_protocol = px.bar(
            x=protocol_counts.index, y=protocol_counts.values,
            labels={"x": "Protocol", "y": "Count"},
            title=f"{label} - Protocol Distribution"
        )
        fig_protocol.update_traces(text=protocol_counts.values, textposition="outside", cliponaxis=False)
        scale_bar_figure(fig_protocol, tick_angle=-20)
        add_chart("Protocol Distribution", fig_protocol, filter_column="protocol", filter_source="x")

    table_df = df.drop(columns=["timestamp_dt"], errors="ignore")
    table_html, table_column_map = generate_logs_table(table_df)
    export_panel = generate_export_panel(case_id, vendor)

    total_events = len(df)
    category_total = df["log_category"].fillna("unknown").astype(str).str.lower().ne("unknown").sum()
    blocked_failed = df["outcome"].isin(["blocked", "failed"]).sum()
    unknown_outcome = df["outcome"].fillna("unknown").astype(str).str.lower().eq("unknown").sum()
    timestamp_valid = df["timestamp_dt"].notna().sum()
    unique_src_ips = df["src_ip"].fillna("").astype(str).str.strip().replace("", pd.NA).dropna().nunique()
    unique_dst_ips = df["dst_ip"].fillna("").astype(str).str.strip().replace("", pd.NA).dropna().nunique()
    top_severity = severity_counts.index[0] if not severity_counts.empty else "INFO"
    category_pct = (category_total / total_events * 100.0) if total_events else 0.0
    timestamp_pct = (timestamp_valid / total_events * 100.0) if total_events else 0.0
    stats_html = f"""
      <div class="stats-grid">
        <div class="stat-card"><div class="label">Total Events</div><div class="value">{int(total_events)}</div></div>
        <div class="stat-card"><div class="label">Categorized Events</div><div class="value">{int(category_total)} ({category_pct:.1f}%)</div></div>
        <div class="stat-card"><div class="label">Blocked/Failed</div><div class="value">{int(blocked_failed)}</div></div>
        <div class="stat-card"><div class="label">Unknown Outcome</div><div class="value">{int(unknown_outcome)}</div></div>
        <div class="stat-card"><div class="label">Timestamp Coverage</div><div class="value">{int(timestamp_valid)} ({timestamp_pct:.1f}%)</div></div>
        <div class="stat-card"><div class="label">Unique Source IPs</div><div class="value">{int(unique_src_ips)}</div></div>
        <div class="stat-card"><div class="label">Unique Destination IPs</div><div class="value">{int(unique_dst_ips)}</div></div>
        <div class="stat-card"><div class="label">Top Severity</div><div class="value">{top_severity}</div></div>
      </div>
    """

    chart_cards = "".join(
        (
            f"<section class='chart-card' data-plotly-id='{html.escape(block['plotly_id'])}' "
            f"data-filter-column='{html.escape(block['filter_column'])}' "
            f"data-filter-source='{html.escape(block['filter_source'])}'>"
            f"<h3 class='chart-title'>{html.escape(block['title'])}</h3>{block['html']}</section>"
        )
        for block in chart_blocks
    )

    table_filter_panel = """
      <div class="panel">
        <h3>Graph-to-Table Filters</h3>
        <p class="filter-hint">Click a chart bar/slice/area to filter log rows by that value.</p>
        <div class="quick-filter-row">
          <button class="quick-filter" type="button" data-quick-filter-column="severity" data-quick-filter-pattern="^(CRITICAL|HIGH)$" data-quick-filter-label="Severity = CRITICAL/HIGH">Critical + High</button>
          <button class="quick-filter" type="button" data-quick-filter-column="outcome" data-quick-filter-pattern="^(blocked|failed)$" data-quick-filter-label="Outcome = blocked/failed">Blocked + Failed</button>
          <button class="quick-filter" type="button" data-quick-filter-column="log_category" data-quick-filter-pattern="^(threat|malware)$" data-quick-filter-label="Category = threat/malware">Threat + Malware</button>
          <button class="quick-filter" type="button" data-quick-filter-column="log_category" data-quick-filter-pattern="^(authentication|vpn)$" data-quick-filter-label="Category = authentication/vpn">Auth + VPN</button>
          <button class="quick-filter" type="button" data-quick-filter-column="action" data-quick-filter-pattern="^(deny|reset|close)$" data-quick-filter-label="Action = deny/reset/close">Deny/Reset/Close</button>
        </div>
        <button id="clearTableFilters" class="button secondary" type="button">Clear Graph Filters</button>
        <p id="activeFilter" class="filter-hint">No graph filters active.</p>
      </div>
    """

    content = f"""
      <h2>Case: {label} ({vendor})</h2>
      {stats_html}
      <div class="chart-grid">{chart_cards}</div>
      {table_filter_panel}
      <h3>Log Records</h3>
      <script id="logsTableColumnMap" type="application/json">{json.dumps(table_column_map)}</script>
      <div class="scroll-box">{table_html}</div>
      {export_panel}
      <br><a href="/">Back</a>
    """
    return render_page(label, f"Case: {label} ({vendor})", content, use_datatables=True)

@app.route("/export", methods=["POST"])
def export_es():
    case_id = request.form.get("case_id")
    es_url = request.form.get("es_url", "http://localhost:9200")
    es_index = request.form.get("es_index", "logs")
    es_user = request.form.get("es_user", "")
    es_pass = request.form.get("es_pass", "")
    case, parsed_data = load_case_data(case_id)
    if not case:
        return render_page("Error", "Error", parsed_data)
    vendor = case["vendor"]
    export_records = normalized_records_for_case(case, parsed_data)
    if not export_records:
        return render_page(
            "Export Success",
            "Elasticsearch Export",
            f"No records available to export for case '{html.escape(case['label'])}'. <a href='/case/{case_id}'>Back</a>",
        )
    if es_user and es_pass:
        es = Elasticsearch([es_url], http_auth=(es_user, es_pass))
    else:
        es = Elasticsearch([es_url])
    parser_instance = PARSERS.get(vendor)()
    mapping = parser_instance.get_elasticsearch_mapping()
    if not es.indices.exists(index=es_index):
        es.indices.create(index=es_index, body=mapping, ignore=400)
    actions = [{"_index": es_index, "_source": rec} for rec in export_records]
    helpers.bulk(es, actions)
    return render_page("Export Success", "Elasticsearch Export", f"Logs exported to Elasticsearch index '{es_index}'. <a href='/case/{case_id}'>Back</a>")

@app.route("/export_influx", methods=["POST"])
def export_influx():
    case_id = request.form.get("case_id")
    influxdb_url = request.form.get("influxdb_url", "http://localhost:8086")
    influxdb_db = request.form.get("influxdb_db", "logs")
    influxdb_user = request.form.get("influxdb_user", "")
    influxdb_pass = request.form.get("influxdb_pass", "")
    case, parsed_data = load_case_data(case_id)
    if not case:
        return render_page("Error", "Error", parsed_data)
    vendor = case["vendor"]
    export_records = normalized_records_for_case(case, parsed_data)
    if not export_records:
        return render_page(
            "Export Success",
            "InfluxDB Export",
            f"No records available to export for case '{html.escape(case['label'])}'. <a href='/case/{case_id}'>Back</a>",
        )
    try:
        export_to_influxdb(
            export_records,
            vendor,
            influxdb_url,
            influxdb_db,
            influxdb_user,
            influxdb_pass,
            case_id=case.get("sid", ""),
            case_label=case.get("label", ""),
        )
    except Exception as e:
        return render_page("Error", "Error", f"Error exporting to InfluxDB: {e}")
    return render_page("Export Success", "InfluxDB Export", f"Logs exported to InfluxDB database '{influxdb_db}'. <a href='/case/{case_id}'>Back</a>")

@app.route("/export_csv", methods=["POST"])
def export_csv():
    case_id = request.form.get("case_id")
    case, parsed_data = load_case_data(case_id)
    if not case:
        return render_page("Error", "Error", parsed_data)
    export_records = normalized_records_for_case(case, parsed_data)
    df = pd.DataFrame(export_records)
    csv_data = df.to_csv(index=False)
    filename = f"{case['label'].replace(' ', '_')}_logs.csv"
    return Response(csv_data,
                    mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment;filename={filename}"})


@app.route("/export_json", methods=["POST"])
def export_json():
    case_id = request.form.get("case_id")
    case, parsed_data = load_case_data(case_id)
    if not case:
        return render_page("Error", "Error", parsed_data)
    export_records = normalized_records_for_case(case, parsed_data)
    json_payload = json.dumps(export_records, ensure_ascii=False, indent=2, default=str)
    filename = f"{case['label'].replace(' ', '_')}_logs.json"
    return Response(
        json_payload,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

