# EFLP v0.1.1

Flask-based forensic analysis application that ingests multi-vendor firewall logs, normalizes records into a common schema, and provides a case-centric investigation UI with charts, searchable tables, and export pipelines.

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

- High-level stats cards (total events, categorized events, blocked/failed, top severity)
- Severity distribution
- Forensic category distribution
- Outcome breakdown
- Top security events
- Top source IPs
- Top user identities
- Authentication and VPN outcomes
- Configuration/system activity
- Time-bucketed category timeline
- Network type distribution

Raw logs are also shown in an interactive DataTable (sorting, paging, filtering).

### Export pipelines
From a case page, users can export normalized data to:

- Elasticsearch (bulk index with parser-provided mapping)
- InfluxDB (measurement `logs` with tags/fields)
- CSV download

## Architecture

In Docker Compose mode (`/eflp`):

- `eflp_app`: Flask + Gunicorn application (`:5000`)
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
- Neo4j browser: `http://localhost:7474` (default auth in compose is `neo4j/testuser`)


## Supported Input Types

Upload accepts:

- `.log`
- `.txt`
- `.csv`
- `.tsv`

CSV/TSV inputs are read directly into records; other formats are parsed by vendor-specific parsers.
