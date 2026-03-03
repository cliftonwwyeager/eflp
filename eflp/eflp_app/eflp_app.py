import os
import io
import uuid
import base64
import pytz
import pandas as pd
import plotly.express as px
from flask import Flask, request, Response, render_template_string, send_file
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

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>{{ title }}</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --bg: #070b10;
      --panel: #0e1724;
      --panel-soft: #101f31;
      --border: #1e7b63;
      --accent: #30f2b3;
      --text: #d8fff2;
      --muted: #86b9a8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background:
        radial-gradient(1000px 300px at 0% 0%, #123529 0%, transparent 70%),
        radial-gradient(900px 260px at 100% 0%, #162138 0%, transparent 65%),
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
      background: linear-gradient(140deg, #0c1b25, #09111a);
      border: 1px solid var(--border);
      border-radius: 14px;
      margin-bottom: 18px;
      padding: 14px 18px;
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
      background: linear-gradient(170deg, rgba(16,31,49,0.9), rgba(8,15,25,0.9));
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      margin: 10px 0;
    }
    input, select {
      width: 100%;
      margin: 6px 0;
      padding: 10px 12px;
      color: var(--text);
      background: #0b1521;
      border: 1px solid #236f5c;
      border-radius: 8px;
    }
    .button {
      margin-top: 8px;
      padding: 10px 16px;
      color: #072518;
      font-weight: 700;
      border: 0;
      border-radius: 9px;
      background: linear-gradient(110deg, #53ffce, #2ee7aa);
      cursor: pointer;
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
      border: 1px solid #1b6654;
      padding: 7px 10px;
      text-align: left;
    }
    th {
      background: #102133;
      color: var(--accent);
      position: sticky;
      top: 0;
      z-index: 1;
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
  .dataTables_wrapper { color: #d8fff2 !important; }
  .dataTables_wrapper .dataTables_filter input,
  .dataTables_wrapper .dataTables_length select {
    color: #d8fff2 !important;
    background: #0b1521 !important;
    border: 1px solid #236f5c !important;
  }
  .dataTables_wrapper .dataTables_paginate .paginate_button {
    color: #53ffce !important;
  }
</style>
<script>
  $(document).ready(function() {
    $('#logsTable').DataTable({
      pageLength: 25,
      order: [[0, 'desc']]
    });
  });
</script>
"""

def render_page(title, header, content, use_datatables=False):
    dt = DATATABLES if use_datatables else ""
    return render_template_string(BASE_TEMPLATE, title=title, header=header, content=content, datatables=dt)

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

def parse_uploaded_file(file_path, vendor):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in [".csv", ".tsv"]:
        sep = "," if ext == ".csv" else "\t"
        try:
            df = pd.read_csv(file_path, sep=sep)
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
    vendor = case["vendor"]
    file_path = case["path"]
    try:
        parsed_data = parse_uploaded_file(file_path, vendor)
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
    for col in columns:
        if col not in df.columns:
            df[col] = ""
    records = df[columns].fillna("").astype(str).to_dict("records")
    head = "<tr>" + "".join(f"<th>{col}</th>" for col in columns) + "</tr>"
    rows = "".join("<tr>" + "".join(f"<td>{rec[col]}</td>" for col in columns) + "</tr>" for rec in records)
    return f"<table id='logsTable'><thead>{head}</thead><tbody>{rows}</tbody></table>"

def generate_export_forms(case_id, vendor):
    es_form = f"""
    <form action="/export" method="post" style="margin-bottom:15px;">
      <input type="hidden" name="case_id" value="{case_id}" />
      <label>Elasticsearch URL:</label>
      <input type="text" name="es_url" value="http://localhost:9200" />
      <label>Index:</label>
      <input type="text" name="es_index" value="{vendor}_logs" />
      <label>ES Username:</label>
      <input type="text" name="es_user" />
      <label>ES Password:</label>
      <input type="password" name="es_pass" />
      <input class="button" type="submit" value="Export to Elasticsearch" />
    </form>
    """
    influx_form = f"""
    <form action="/export_influx" method="post" style="margin-bottom:15px;">
      <input type="hidden" name="case_id" value="{case_id}" />
      <label>InfluxDB URL:</label>
      <input type="text" name="influxdb_url" value="http://localhost:8086" />
      <label>Database:</label>
      <input type="text" name="influxdb_db" value="{vendor}_logs" />
      <label>InfluxDB Username:</label>
      <input type="text" name="influxdb_user" />
      <label>InfluxDB Password:</label>
      <input type="password" name="influxdb_pass" />
      <input class="button" type="submit" value="Export to InfluxDB" />
    </form>
    """
    csv_form = f"""
    <form action="/export_csv" method="post" style="margin-bottom:15px;">
      <input type="hidden" name="case_id" value="{case_id}" />
      <input class="button" type="submit" value="Export to CSV" />
    </form>
    """
    return es_form + influx_form + csv_form

def export_to_influxdb(parsed_data, vendor, influxdb_url, influxdb_db, influxdb_user, influxdb_pass):
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
        ]).lower()
        t = "unknown"
        if any(k in s for k in ["sslvpn", "nsvpn", "vpn", "citrix gateway", "globalprotect"]):
            t = "sslvpn"
        elif any(k in s for k in ["ike", "ipsec"]):
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

def infer_log_category_from_text(text: str) -> str:
    s = str(text or "").lower()
    if any(k in s for k in ["threat", "intrusion", "ips", "ids", "attack", "exploit", "signature"]):
        return "threat"
    if any(k in s for k in ["malware", "virus", "spyware", "ransomware", "botnet"]):
        return "malware"
    if any(k in s for k in ["auth", "login", "logout", "radius", "ldap", "saml", "mfa"]):
        return "authentication"
    if any(k in s for k in ["vpn", "ipsec", "ike", "sslvpn", "globalprotect", "tunnel"]):
        return "vpn"
    if any(k in s for k in ["config", "policy install", "commit", "admin", "change", "audit"]):
        return "configuration"
    if any(k in s for k in ["system", "daemon", "kernel", "cpu", "memory", "fan", "health"]):
        return "system"
    if any(k in s for k in ["dns", "domain", "resolver", "query"]):
        return "dns"
    if any(k in s for k in ["url", "web", "http", "https", "proxy"]):
        return "web"
    if any(k in s for k in ["ha", "cluster", "failover", "sync"]):
        return "ha"
    if any(k in s for k in ["route", "bgp", "ospf", "rip"]):
        return "routing"
    if any(k in s for k in ["wireless", "wifi", "ssid", "ap "]):
        return "wireless"
    if any(k in s for k in ["nat", "session", "flow", "traffic", "connection", "firewall", "packet"]):
        return "traffic"
    return "unknown"

def infer_outcome_from_text(text: str) -> str:
    s = str(text or "").lower()
    if any(k in s for k in ["deny", "drop", "blocked", "reject", "quarantine"]):
        return "blocked"
    if any(k in s for k in ["fail", "failed", "error", "invalid"]):
        return "failed"
    if any(k in s for k in ["allow", "accept", "permit", "pass"]):
        return "allowed"
    if any(k in s for k in ["success", "authenticated", "ok"]):
        return "success"
    if any(k in s for k in ["detect", "alert", "threat"]):
        return "detected"
    return "unknown"

def normalize_case_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    norm = df.copy()
    norm["timestamp"] = coalesce_columns(norm, ["timestamp", "@timestamp", "time", "event_time", "generated_time"])
    norm["severity"] = coalesce_columns(norm, ["severity", "level", "priority"], default="INFO")
    norm["event"] = coalesce_columns(norm, ["event", "event_type", "subtype", "log_type", "signature"])
    norm["action"] = coalesce_columns(norm, ["action", "palo_action", "result", "status", "disposition"])
    norm["outcome"] = coalesce_columns(norm, ["outcome"])
    norm["log_category"] = coalesce_columns(norm, ["log_category", "category", "type", "subtype"])
    norm["user"] = coalesce_columns(norm, ["user", "username", "src_user", "srcuser", "account", "userid"])
    norm["rule"] = coalesce_columns(norm, ["rule", "policy", "policyid", "policyname", "acl"])
    norm["signature"] = coalesce_columns(norm, ["signature", "threat", "attack", "virusname"])
    norm["src_ip"] = coalesce_columns(norm, ["src_ip", "srcip", "source_ip", "source", "src", "client_ip", "clientip"])
    norm["dst_ip"] = coalesce_columns(norm, ["dst_ip", "dstip", "destination_ip", "destination", "dst", "serverip"])
    norm["src_port"] = coalesce_columns(norm, ["src_port", "srcport", "sport", "spt"])
    norm["dst_port"] = coalesce_columns(norm, ["dst_port", "dstport", "dport", "dpt"])
    norm["protocol"] = coalesce_columns(norm, ["protocol", "proto", "service"])
    norm["message"] = coalesce_columns(norm, ["message", "msg", "description"])
    norm["event_id"] = coalesce_columns(norm, ["event_id", "eventid", "logid", "id", "msgid"])
    norm["session_id"] = coalesce_columns(norm, ["session_id", "sessionid", "sid", "connid", "flowid"])

    sev_map = {
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
        "INFORMATION": "INFO",
        "DEBUG": "INFO",
    }
    norm["severity"] = norm["severity"].fillna("").astype(str).str.upper().replace(sev_map)
    norm.loc[norm["severity"].str.strip().eq(""), "severity"] = "INFO"

    missing_category = norm["log_category"].fillna("").astype(str).str.strip().eq("")
    if missing_category.any():
        category_seed = (
            norm["message"].fillna("").astype(str) + " " +
            norm["event"].fillna("").astype(str) + " " +
            norm["action"].fillna("").astype(str)
        )
        norm.loc[missing_category, "log_category"] = category_seed[missing_category].map(infer_log_category_from_text)

    missing_outcome = norm["outcome"].fillna("").astype(str).str.strip().eq("")
    if missing_outcome.any():
        outcome_seed = norm["action"].fillna("").astype(str) + " " + norm["message"].fillna("").astype(str)
        norm.loc[missing_outcome, "outcome"] = outcome_seed[missing_outcome].map(infer_outcome_from_text)

    norm["log_category"] = norm["log_category"].fillna("").astype(str).str.lower()
    norm["outcome"] = norm["outcome"].fillna("").astype(str).str.lower()

    norm = ensure_network_type(norm)
    norm["timestamp_dt"] = pd.to_datetime(norm["timestamp"], errors="coerce", utc=True)

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
      <p style="margin-top:0;color:#86b9a8;">Upload a vendor dump and EFLP will normalize traffic, authentication, VPN, threat, system, and configuration events for forensic triage.</p>
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
        <input type="file" name="logfile" accept=".log,.txt,.csv,.tsv" />
        <input class="button" type="submit" value="Upload" />
      </form>
    </div>
    """
    content = case_box + upload_form
    return render_page("EFLP", "EFLP v0.0.9-2", content)

@app.route("/upload", methods=["POST"])
def upload():
    label = request.form.get("label", "Untitled")
    vendor = request.form.get("vendor")
    uploaded_file = request.files.get("logfile")
    if not uploaded_file or uploaded_file.filename == "":
        return "No file selected"
    case_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOADS, secure_filename(uploaded_file.filename))
    uploaded_file.save(file_path)
    store_case(case_id, label, vendor, file_path)
    return render_page("Case Created", "Case Created", f"Case '{label}' created. <a href='/case/{case_id}'>View</a>")

@app.route("/case/<case_id>")
def view_case(case_id):
    case, result = load_case_data(case_id)
    if not case:
        return render_page("Error", "Error", result)
    vendor = case["vendor"]
    label = case["label"]
    df = pd.DataFrame(result)

    if df.empty:
        return render_page(label, f"Case: {label} ({vendor})",
                           f"<h2>Case: {label} ({vendor})</h2><p>No records parsed.</p><br><a href='/'>Back</a>")

    df = normalize_case_dataframe(df)

    chart_blocks = []
    plotly_loaded = False

    def fig_to_html(fig):
        nonlocal plotly_loaded
        include = "cdn" if not plotly_loaded else False
        plotly_loaded = True
        return fig.to_html(full_html=False, include_plotlyjs=include)

    def add_chart(title, fig):
        chart_blocks.append((title, fig_to_html(fig)))

    severity_counts = df["severity"].fillna("INFO").astype(str).str.upper().value_counts()
    if not severity_counts.empty:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        ordered_index = [s for s in severity_order if s in severity_counts.index] + [s for s in severity_counts.index if s not in severity_order]
        severity_counts = severity_counts.reindex(ordered_index)
        fig_sev = px.bar(
            x=severity_counts.index, y=severity_counts.values,
            labels={"x": "Severity", "y": "Count"},
            title=f"{label} – Event Severity Distribution",
            template="plotly_dark"
        )
        fig_sev.update_traces(text=severity_counts.values, textposition="outside")
        add_chart("Severity Distribution", fig_sev)

    category_counts = df["log_category"].fillna("unknown").astype(str).replace("", "unknown").value_counts()
    if not category_counts.empty:
        fig_category = px.bar(
            x=category_counts.index, y=category_counts.values,
            labels={"x": "Log Category", "y": "Count"},
            title=f"{label} – Forensic Log Category Distribution",
            template="plotly_dark"
        )
        fig_category.update_traces(text=category_counts.values, textposition="outside")
        add_chart("Forensic Category Distribution", fig_category)

    outcome_counts = df["outcome"].fillna("unknown").astype(str).replace("", "unknown").value_counts()
    if not outcome_counts.empty:
        fig_outcome = px.pie(
            names=outcome_counts.index, values=outcome_counts.values,
            title=f"{label} – Outcome Breakdown",
            template="plotly_dark", hole=0.35
        )
        add_chart("Outcome Breakdown", fig_outcome)

    event_series = df["event"].fillna("").astype(str)
    if event_series.str.strip().eq("").all():
        event_series = df["message"].astype(str).str.extract(r'\b([A-Z][A-Z0-9_]{3,})\b', expand=False).fillna("misc")
    event_counts = event_series.value_counts()
    if not event_counts.empty:
        top10 = event_counts.head(10)
        other = event_counts.iloc[10:].sum()
        pie_df = top10.reset_index()
        pie_df.columns = ["event", "count"]
        if other:
            pie_df.loc[len(pie_df)] = ["Other", int(other)]
        fig_events = px.pie(
            pie_df, names="event", values="count",
            title=f"{label} – Most Common Security Events",
            template="plotly_dark", hole=0.3
        )
        add_chart("Top Security Events", fig_events)

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
            title=f"{label} – Top {min(20, len(ip_counts))} Source IPs",
            template="plotly_dark"
        )
        fig_ip.update_layout(xaxis={"tickangle": -45})
        fig_ip.update_traces(text=ip_counts.values, textposition="outside")
        add_chart("Top Source IPs", fig_ip)

    user_counts = df["user"].fillna("").astype(str)
    user_counts = user_counts[user_counts.str.strip().ne("")].value_counts().head(15)
    if not user_counts.empty:
        fig_users = px.bar(
            x=user_counts.index, y=user_counts.values,
            labels={"x": "User / Account", "y": "Event Count"},
            title=f"{label} – Top User Identities Observed",
            template="plotly_dark"
        )
        fig_users.update_layout(xaxis={"tickangle": -45})
        fig_users.update_traces(text=user_counts.values, textposition="outside")
        add_chart("Top User Identities", fig_users)

    auth_df = df[df["log_category"].isin(["authentication", "vpn"])].copy()
    if not auth_df.empty:
        auth_df["outcome"] = auth_df["outcome"].fillna("unknown").replace("", "unknown")
        auth_counts = auth_df.groupby(["log_category", "outcome"]).size().reset_index(name="count")
        fig_auth = px.bar(
            auth_counts, x="outcome", y="count", color="log_category",
            labels={"outcome": "Outcome", "count": "Count", "log_category": "Category"},
            title=f"{label} – Authentication & VPN Outcomes",
            template="plotly_dark", barmode="group"
        )
        add_chart("Authentication & VPN Outcomes", fig_auth)

    cfg_df = df[df["log_category"].isin(["configuration", "system", "ha", "routing"])].copy()
    if not cfg_df.empty:
        cfg_events = cfg_df["event"].fillna("unknown").astype(str).replace("", "unknown").value_counts().head(12)
        if not cfg_events.empty:
            fig_cfg = px.bar(
                x=cfg_events.index, y=cfg_events.values,
                labels={"x": "Config/System Event", "y": "Count"},
                title=f"{label} – Configuration & System Change Activity",
                template="plotly_dark"
            )
            fig_cfg.update_layout(xaxis={"tickangle": -45})
            fig_cfg.update_traces(text=cfg_events.values, textposition="outside")
            add_chart("Configuration and System Activity", fig_cfg)

    timeline_df = df.dropna(subset=["timestamp_dt"]).copy()
    if not timeline_df.empty:
        timeline_df["hour_bucket"] = timeline_df["timestamp_dt"].dt.floor("h")
        timeline_counts = timeline_df.groupby(["hour_bucket", "log_category"]).size().reset_index(name="count")
        fig_timeline = px.area(
            timeline_counts, x="hour_bucket", y="count", color="log_category",
            labels={"hour_bucket": "Time", "count": "Events", "log_category": "Category"},
            title=f"{label} – Event Timeline by Log Category",
            template="plotly_dark"
        )
        add_chart("Category Timeline", fig_timeline)

    nt_counts = df["network_type"].fillna("unknown").astype(str).replace("", "unknown").value_counts()
    if not nt_counts.empty:
        fig_nt = px.bar(
            x=nt_counts.index, y=nt_counts.values,
            labels={"x": "Network Type", "y": "Count"},
            title=f"{label} – Distribution by Network Type",
            template="plotly_dark"
        )
        fig_nt.update_traces(text=nt_counts.values, textposition="outside")
        add_chart("Network Type Distribution", fig_nt)

    table_df = df.drop(columns=["timestamp_dt"], errors="ignore")
    table_html = generate_logs_table(table_df)
    export_forms = generate_export_forms(case_id, vendor)

    total_events = len(df)
    category_total = df["log_category"].fillna("unknown").astype(str).str.lower().ne("unknown").sum()
    blocked_failed = df["outcome"].isin(["blocked", "failed"]).sum()
    top_severity = severity_counts.index[0] if not severity_counts.empty else "INFO"
    stats_html = f"""
      <div class="stats-grid">
        <div class="stat-card"><div class="label">Total Events</div><div class="value">{int(total_events)}</div></div>
        <div class="stat-card"><div class="label">Categorized Events</div><div class="value">{int(category_total)}</div></div>
        <div class="stat-card"><div class="label">Blocked/Failed</div><div class="value">{int(blocked_failed)}</div></div>
        <div class="stat-card"><div class="label">Top Severity</div><div class="value">{top_severity}</div></div>
      </div>
    """

    chart_cards = "".join(
        f"<section class='chart-card'><h3 class='chart-title'>{title}</h3>{html}</section>"
        for title, html in chart_blocks
    )

    content = f"""
      <h2>Case: {label} ({vendor})</h2>
      {stats_html}
      <div class="chart-grid">{chart_cards}</div>
      <h3>Log Records</h3>
      <div class="scroll-box">{table_html}</div>
      <div class="panel">
        <h3>Export Options</h3>
        {export_forms}
      </div>
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
    if es_user and es_pass:
        es = Elasticsearch([es_url], http_auth=(es_user, es_pass))
    else:
        es = Elasticsearch([es_url])
    parser_instance = PARSERS.get(vendor)()
    mapping = parser_instance.get_elasticsearch_mapping()
    if not es.indices.exists(index=es_index):
        es.indices.create(index=es_index, body=mapping, ignore=400)
    actions = [{"_index": es_index, "_source": rec} for rec in parsed_data]
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
    try:
        export_to_influxdb(parsed_data, vendor, influxdb_url, influxdb_db, influxdb_user, influxdb_pass)
    except Exception as e:
        return render_page("Error", "Error", f"Error exporting to InfluxDB: {e}")
    return render_page("Export Success", "InfluxDB Export", f"Logs exported to InfluxDB database '{influxdb_db}'. <a href='/case/{case_id}'>Back</a>")

@app.route("/export_csv", methods=["POST"])
def export_csv():
    case_id = request.form.get("case_id")
    case, parsed_data = load_case_data(case_id)
    if not case:
        return render_page("Error", "Error", parsed_data)
    df = pd.DataFrame(parsed_data)
    csv_data = df.to_csv(index=False)
    filename = f"{case['label'].replace(' ', '_')}_logs.csv"
    return Response(csv_data,
                    mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment;filename={filename}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
