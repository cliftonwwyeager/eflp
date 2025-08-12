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
from parsers.netscaler_parser import NetscalerParser  # NEW

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
  <style>
    body { 
      background-color: #000000; 
      color: #00FF00; 
      font-family: 'Courier New', Courier, monospace; 
      margin: 20px;
    }
    header { 
      background-color: #000000; 
      padding: 10px 20px; 
      border: 1px solid #00FF00; 
      border-radius: 5px; 
      margin-bottom: 20px;
    }
    header h1 { 
      margin: 0; 
      font-size: 24px; 
    }
    nav a { 
      margin-right: 15px; 
      color: #00FF00; 
      text-decoration: none; 
    }
    nav a:hover { 
      text-decoration: underline; 
    }
    .container { 
      max-width: 1000px; 
      margin: 0 auto; 
    }
    input, select {
      background-color: #000000; 
      border: 1px solid #00FF00; 
      color: #00FF00; 
      padding: 8px; 
      border-radius: 3px; 
      margin: 5px 0; 
      width: 100%;
      box-sizing: border-box;
    }
    .button { 
      background-color: #000000; 
      color: #00FF00; 
      border: 1px solid #00FF00; 
      padding: 10px 15px; 
      cursor: pointer; 
      border-radius: 3px; 
      margin-top: 10px; 
    }
    .button:hover { 
      background-color: #003300; 
    }
    table { 
      border-collapse: collapse; 
      width: 100%; 
      margin-bottom: 20px; 
    }
    th, td { 
      border: 1px solid #00FF00; 
      padding: 8px 12px; 
    }
    th { 
      background-color: #000000; 
    }
    .scroll-box { 
      max-height: 400px; 
      overflow-y: auto; 
      border: 1px solid #00FF00; 
      padding: 10px; 
      border-radius: 3px; 
      margin-bottom: 20px;
    }
    .case-box { 
      border: 1px solid #00FF00; 
      padding: 10px; 
      margin: 10px 0; 
      border-radius: 3px; 
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
<script>
  $(document).ready(function() {
    $('#logsTable').DataTable();
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
        "timestamp", "severity", "event", "action", "network_type",
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "message"
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
                "subtype": rec.get("subtype", ""),
                "object": rec.get("object", ""),
            },
            "time": iso_time,
            "fields": {
                "message": rec.get("message", ""),
                "record_id": rec.get("record_id", ""),
                "event_id": rec.get("event_id", "")
            }
        }
        points.append(point)
    client.write_points(points)

def ensure_network_type(df: pd.DataFrame) -> pd.DataFrame:
    if "network_type" in df.columns:
        return df
    nts = []
    for _, row in df.iterrows():
        s = " ".join(str(x) for x in [
            row.get("message", ""),
            row.get("severity", ""),
            row.get("subtype", ""),
            row.get("object", "")
        ]).lower()
        t = "unknown"
        if any(k in s for k in ["sslvpn", "nsvpn", "vpn", "citrix gateway"]):
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
    <h2>Upload Logs</h2>
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

    if "severity" not in df.columns:
        table_html = df.head(10).to_html(index=False, border=0)
        content = f"<h2>Case: {label} ({vendor})</h2><p>No 'severity' column found. Showing first 10 rows:</p>{table_html}<br><a href='/'>Back</a>"
        return render_page(label, f"Case: {label} ({vendor})", content)

    for c in ["event", "message", "src_ip"]:
        if c not in df.columns:
            df[c] = ""

    df = ensure_network_type(df)

    severity_counts = df["severity"].fillna("").astype(str).value_counts().sort_index()
    fig_sev = px.bar(
        x=severity_counts.index, y=severity_counts.values,
        labels={"x": "Severity", "y": "Count"},
        title=f"{label} – Event Severity Distribution",
        template="plotly_dark"
    )
    fig_sev.update_traces(text=severity_counts.values, textposition='outside')
    chart_sev = fig_sev.to_html(full_html=False, include_plotlyjs='cdn')

    event_series = df["event"]
    if event_series.fillna("").eq("").all() and "subtype" in df.columns:
        event_series = df["subtype"].astype(str)
    if event_series.fillna("").eq("").all():
        event_series = df["message"].astype(str).str.extract(r'\\b(APPFW_[A-Z0-9_]+)\\b', expand=False).fillna("misc")

    event_counts = event_series.value_counts()
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
    chart_events = fig_events.to_html(full_html=False, include_plotlyjs=False)

    ip_field_candidates = ["src_ip", "client_ip", "source", "src"]
    ip_field = next((f for f in ip_field_candidates if f in df.columns and not df[f].isna().all()), None)
    if not ip_field:
        df["ip_for_count"] = df["message"].astype(str).str.extract(r'((?:\\d{1,3}\\.){3}\\d{1,3})', expand=False)
        ip_field = "ip_for_count"

    ip_counts = df[ip_field].dropna().astype(str)
    ip_counts = ip_counts[ip_counts.str.len() > 0].value_counts().head(20)
    fig_ip = px.bar(
        x=ip_counts.index, y=ip_counts.values,
        labels={"x": "IP Address", "y": "Hits"},
        title=f"{label} – Top {min(20, len(ip_counts))} IPs by Hits",
        template="plotly_dark"
    )
    fig_ip.update_layout(xaxis={'tickangle': -45})
    fig_ip.update_traces(text=ip_counts.values, textposition='outside')
    chart_ip = fig_ip.to_html(full_html=False, include_plotlyjs=False)

    nt_counts = df["network_type"].fillna("unknown").astype(str).value_counts()
    fig_nt = px.bar(
        x=nt_counts.index, y=nt_counts.values,
        labels={"x": "Network Type", "y": "Count"},
        title=f"{label} – Distribution by Network Type",
        template="plotly_dark"
    )
   
    fig_nt.update_traces(text=nt_counts.values, textposition='outside')
    chart_nt = fig_nt.to_html(full_html=False, include_plotlyjs=False)
    table_html = generate_logs_table(df)
    export_forms = generate_export_forms(case_id, vendor)

    content = f"""
      <h2>Case: {label} ({vendor})</h2>
      {chart_sev}
      {chart_events}
      {chart_ip}
      {chart_nt}
      <h3>Log Records</h3>
      <div class="scroll-box">{table_html}</div>
      <h3>Export Options</h3>
      {export_forms}
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
