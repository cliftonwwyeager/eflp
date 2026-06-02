# EFLP v0.1.4
Flask-based forensic analysis application that ingests uploaded and real-time syslog firewall logs, normalizes records into a common schema, and provides case-centric investigation UI with static and live dashboards, searchable tables, and export pipelines.

### Multi-vendor parser coverage
EFLP currently includes parser implementations for:

- Palo Alto
- Fortigate
- SonicWall
- Cisco FTD
- Check Point
- Meraki
- UniFi
- Juniper
- WatchGuard
- Sophos UTM
- Sophos XGS
- Netscaler (Citrix ADC)

### Unified Formatting
Regardless of input vendor/format, records are normalized into consistent fields used for triage and downstream export, including:

- `timestamp`, `vendor`, `severity`, `severity_int`
- `log_category`, `event`, `action`, `outcome`
- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
- `user`, `rule`, `signature`, `event_id`, `session_id`
- `network_type`, `message`, `raw_fields`

Normalization also infers missing values for:
- Severity (including syslog-priority mapping)
- Action and outcome
- Log category (e.g. traffic, authentication, vpn, threat, system, configuration, dns, web, ha, routing, wireless)
- Network type (e.g. sslvpn, ike, appfw, wan, lan, dmz)

### Case management backed by Neo4j
Uploaded files are tracked as cases in Neo4j with:

- Case UUID (`sid`)
- Label
- Vendor
- Stored upload path
- Creation timestamp

The home page lists all saved cases and links directly to case dashboards.

### Investigation dashboard and visual analytics
Each case view renders:

- High-level stats cards (total events, categorized events, blocked/failed, coverage, source/destination counts)
- Severity distribution
- Forensic category distribution
- Outcome breakdown
- Top security events
- Top source IPs
- Top destination IPs
- Top user identities
- Authentication and VPN outcomes
- Configuration/system activity
- Time-bucketed category timeline
- Network type distribution
- Protocol distribution

Raw logs are also shown in an interactive DataTable (sorting, paging, filtering).

### Real-time syslog ingestion
EFLP can listen for UDP syslog and append incoming firewall events to live cases in real time.

- Default listener: `0.0.0.0:5514/udp`
- Home page workflow: create a Live Syslog case, choose the firewall vendor, and optionally restrict routing to one source IP or CIDR.
- Live dashboard: `/live/<case_id>` refreshes every two seconds with severity, category, outcome, timeline, top source, top destination, top 10 IPs by traffic amount, top 10 rules by traffic amount, and recent-event views.
- Storage: live events append to `<case_id>.live.jsonl` and are also cached in memory for fast dashboard updates.

Environment controls:

- `EFLP_SYSLOG_ENABLED=true|false`
- `EFLP_SYSLOG_HOST=0.0.0.0`
- `EFLP_SYSLOG_PORT=5514`
- `EFLP_LIVE_CASE_CACHE_LIMIT=100000`
- `EFLP_LIVE_DASHBOARD_WINDOW=5000`

### Export pipelines
From a case page, users can export normalized data to:

- Elasticsearch (bulk index with parser-provided mapping)
- InfluxDB (measurement `logs` with tags/fields)
- CSV download
- JSON download

## Architecture

In Docker Compose mode (`/eflp`):

- `eflp_app`: Flask application (`:5000`; the all-in-one image runs it under gunicorn)
- UDP syslog listener in the app process (`:5514/udp` by default)
- `neo4j`: case metadata graph store (`:7474`, `:7687`)
- `nginx`: TLS reverse proxy with HTTP->HTTPS redirect (`:8080`, `:8443`)

Request flow:

1. Browser -> Nginx (`https://localhost:8443`)
2. Nginx -> Flask app (`http://eflp_app:5000`)
3. Flask app -> Neo4j for case metadata
4. Optional exports -> Elasticsearch / InfluxDB

## Quick Start (Docker Compose)


```bash
docker compose build
docker compose up -d
```

Open:

- `http://localhost:8080` (redirects to HTTPS)
- `https://localhost:8443`
- `http://localhost:5000` (direct app)
- UDP syslog target: `localhost:5514`
- Neo4j browser: `http://localhost:7474` (default auth in compose is `neo4j/testuser`)


## Supported Input Types

Upload accepts:

- `.log`
- `.txt`
- `.csv`
- `.tsv`
- `.tgz`
- `.tar.gz`
CSV/TSV inputs are read directly into records; other formats are parsed by vendor-specific parsers.

