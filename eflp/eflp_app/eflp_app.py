import os
import io
import uuid
import base64
import pytz
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from flask import Flask, request
from dateutil import parser as date_parser
from elasticsearch import Elasticsearch
from werkzeug.utils import secure_filename
from neo4j import GraphDatabase
from parsers.palo_alto_parser import PaloAltoParser
from parsers.fortigate_parser import FortigateParser
from parsers.sonicwall_parser import SonicwallParser
from parsers.cisco_ftd_parser import CiscoFTDParser
from parsers.checkpoint_parser import CheckpointParser
from parsers.meraki_parser import MerakiParser  # <-- New import

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
    "meraki": MerakiParser  # <-- New vendor added here
}

STYLE = """
<style>
body { background-color:black; color:#00FF00; font-family:Arial,sans-serif; margin:20px; }
h1, h2, h3, label, table, th, td, input, select, option, form, p { color:#00FF00; }
a { color:#00FF00; text-decoration:none; }
a:hover { text-decoration:underline; }
input, select { background-color:#333; border:1px solid #00FF00; color:#00FF00; margin:5px 0; padding:5px; }
table { border-collapse:collapse; }
th, td { border:1px solid #00FF00; padding:6px 8px; }
.button { background-color:#333; color:#00FF00; border:1px solid #00FF00; padding:8px 12px; cursor:pointer; margin-top:10px; }
.button:hover { background-color:#444; }
.scroll-box { max-height:300px; overflow-y:auto; margin-top:20px; border:1px solid #00FF00; padding:5px; }
.case-box { border:1px solid #00FF00; padding:5px; margin:10px 0; }
</style>
"""

def store_case(case_id, label, vendor, path):
    with driver.session() as s:
        s.run("""
        CREATE (c:Case {
            sid:$sid,
            label:$label,
            vendor:$vendor,
            path:$path,
            created:timestamp()
        })
        """, sid=case_id, label=label, vendor=vendor, path=path)

def get_all_cases():
    with driver.session() as s:
        res = s.run("""
        MATCH (c:Case)
        RETURN c.sid AS sid, c.label AS label, c.vendor AS vendor
        ORDER BY c.created DESC
        """)
        return res.data()

def get_case_by_sid(case_id):
    with driver.session() as s:
        r = s.run("MATCH (c:Case {sid:$sid}) RETURN c LIMIT 1", sid=case_id).single()
        return r["c"] if r else None

@app.route("/")
def index():
    cases = get_all_cases()
    box = "<div class='case-box'><h3>All Cases</h3>"
    if cases:
        for c in cases:
            box += f"<p><a href='/case/{c['sid']}'>{c['label']} ({c['vendor']})</a></p>"
    else:
        box += "<p>No cases found.</p>"
    box += "</div>"
    return f"""
    <html>
    <head><title>EFLP</title>{STYLE}</head>
    <body>
    <h1>EFLP v0.0.5</h1>
    {box}
    <h2>Upload Logs</h2>
    <form action="/upload" method="post" enctype="multipart/form-data">
      <label>Case Label:</label><br>
      <input type="text" name="label" placeholder="Case label" /><br><br>
      <label>Vendor:</label><br>
      <select name="vendor">
        <option value="palo_alto">Palo Alto</option>
        <option value="fortigate">Fortigate</option>
        <option value="sonicwall">SonicWall</option>
        <option value="cisco_ftd">Cisco FTD</option>
        <option value="checkpoint">Check Point</option>
        <option value="meraki">Meraki</option> <!-- New option added -->
      </select><br><br>
      <label>Log File:</label><br>
      <input type="file" name="logfile" accept=".log,.txt" /><br><br>
      <input class="button" type="submit" value="Upload" />
    </form>
    </body>
    </html>
    """

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
    return f"Case '{label}' created. <a href='/case/{case_id}'>View</a>"

@app.route("/case/<case_id>")
def view_case(case_id):
    c = get_case_by_sid(case_id)
    if not c:
        return "Case not found. <a href='/'>Back</a>"
    vendor = c["vendor"]
    label = c["label"]
    file_path = c["path"]
    parser_cls = PARSERS.get(vendor)
    if not parser_cls:
        return f"Unknown vendor: {vendor} <a href='/'>Back</a>"

    parser = parser_cls()
    parsed_data = parser.parse(file_path)
    df = pd.DataFrame(parsed_data)

    if "severity" not in df.columns:
        h = df.head(10).to_html(index=False, border=0)
        return f"""
        <html>
        <head><title>{label}</title>{STYLE}</head>
        <body>
        <h2>Case: {label} ({vendor})</h2>
        <p>No 'severity' column found. Showing first 10 rows:</p>
        {h}
        <form action="/export" method="post">
          <input type="hidden" name="case_id" value="{case_id}" />
          <label>Elasticsearch URL:</label><br>
          <input type="text" name="es_url" value="http://localhost:9200" /><br><br>
          <label>Index:</label><br>
          <input type="text" name="es_index" value="{vendor}_logs" /><br><br>
          <label>ES Username:</label><br>
          <input type="text" name="es_user" /><br><br>
          <label>ES Password:</label><br>
          <input type="password" name="es_pass" /><br><br>
          <input class="button" type="submit" value="Export" />
        </form>
        <br><a href="/">Back</a>
        </body>
        </html>
        """
    cts = df["severity"].value_counts().sort_index()
    colors = ["red","green","blue","orange","purple","yellow","cyan","magenta","lime","pink"]
    fig, ax = plt.subplots()
    cts.plot(kind="bar", ax=ax, color=colors[:len(cts)])
    ax.set_title(f"{label} Severity", color="#00FF00")
    ax.set_xlabel("Severity", color="#00FF00")
    ax.set_ylabel("Count", color="#00FF00")
    fig.patch.set_facecolor("black")
    ax.set_facecolor("black")
    for lbl in ax.get_xticklabels() + ax.get_yticklabels():
        lbl.set_color("#00FF00")
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png", facecolor=fig.get_facecolor())
    buf.seek(0)
    encoded_png = base64.b64encode(buf.getvalue()).decode("utf-8")
    plt.close()

    columns = ["timestamp", "severity", "message"]
    for col in columns:
        if col not in df.columns:
            df[col] = ""
    df_records = df[columns].to_dict("records")
    table_head = "<tr>" + "".join(f"<th>{c.capitalize()}</th>" for c in columns) + "</tr>"
    table_rows = []
    for rec in df_records:
        row = "<tr>" + "".join(f"<td>{rec[c]}</td>" for c in columns) + "</tr>"
        table_rows.append(row)
    scroll_table = f"<div class='scroll-box'><table><thead>{table_head}</thead><tbody>{''.join(table_rows)}</tbody></table></div>"

    return f"""
    <html>
    <head><title>{label}</title>{STYLE}</head>
    <body>
    <h2>Case: {label} ({vendor})</h2>
    <img src="data:image/png;base64,{encoded_png}" alt="Severity Chart" />
    <h3>Log Records</h3>
    {scroll_table}
    <form action="/export" method="post">
      <input type="hidden" name="case_id" value="{case_id}" />
      <label>Elasticsearch URL:</label><br>
      <input type="text" name="es_url" value="http://localhost:9200" /><br><br>
      <label>Index:</label><br>
      <input type="text" name="es_index" value="{vendor}_logs" /><br><br>
      <label>ES Username:</label><br>
      <input type="text" name="es_user" /><br><br>
      <label>ES Password:</label><br>
      <input type="password" name="es_pass" /><br><br>
      <input class="button" type="submit" value="Export" />
    </form>
    <br><a href="/">Back</a>
    </body>
    </html>
    """

@app.route("/export", methods=["POST"])
def export_es():
    case_id = request.form.get("case_id")
    es_url = request.form.get("es_url","http://localhost:9200")
    es_index = request.form.get("es_index","logs")
    es_user = request.form.get("es_user","")
    es_pass = request.form.get("es_pass","")

    c = get_case_by_sid(case_id)
    if not c:
        return "Case not found. <a href='/'>Back</a>"
    vendor = c["vendor"]
    file_path = c["path"]
    parser_cls = PARSERS.get(vendor)
    if not parser_cls:
        return f"Unknown vendor: {vendor} <a href='/'>Back</a>"

    parser = parser_cls()
    parsed_data = parser.parse(file_path)
    mapping = parser.get_elasticsearch_mapping()

    if es_user and es_pass:
        es = Elasticsearch([es_url], http_auth=(es_user, es_pass))
    else:
        es = Elasticsearch([es_url])

    if not es.indices.exists(index=es_index):
        es.indices.create(index=es_index, body=mapping, ignore=400)

    for rec in parsed_data:
        es.index(index=es_index, document=rec)

    return f"Logs exported to {es_index}. <a href='/case/{case_id}'>Back</a>"
    
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
