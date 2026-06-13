# EFLP v0.1.5

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

The Docker Compose form defaults use service names because exports run from the Flask container:

- Elasticsearch form URL: `http://elasticsearch:9200`
- InfluxDB form URL: `http://influxdb:8086`
- InfluxDB database: `eflp`

Leave those values unchanged when using the Compose stack. `localhost` in an export form would point back to the `eflp_app` container, not to Elasticsearch or InfluxDB.

### Local Granite RAG chat

The stack includes Ollama with `granite4.1:8b` and an XMPP-style chat page at `/chat`.

- Uploaded cases are automatically queued for indexing after parsing.
- Live syslog events are queued as they arrive.
- Retrieval uses the Elasticsearch index `eflp-rag` and can be scoped to one case from the chat toolbar.
- Responses include the retrieved event list and ask Granite to cite those records as `[1]`, `[2]`, and so on.
- The **Sync all cases** button backfills cases created before RAG indexing was enabled.

RAG continually updates the searchable context available to Granite. It does **not** retrain or fine-tune the model weights. The model remains local in Ollama and receives only the retrieved records needed for each chat request.

## Architecture

In Docker Compose mode (`/eflp`):

- `eflp_app`: Flask application (`:5000`; the all-in-one image runs it under gunicorn)
- UDP syslog listener in the app process (`:5514/udp` by default)
- `neo4j`: case metadata graph store (`:7474`, `:7687`)
- `elasticsearch`: manual exports plus the continuously updated `eflp-rag` retrieval index (`:9200`)
- `influxdb`: local time-series export target using the InfluxDB 1.x API (`:8086`)
- `ollama`: local model API with persistent model storage (`:11434`)
- `ollama-model`: one-shot initializer that pulls `granite4.1:8b` before the app starts
- `nginx`: TLS reverse proxy with HTTP->HTTPS redirect (`:8080`, `:8443`)

Request flow:

1. Browser -> Nginx (`https://localhost:8443`)
2. Nginx -> Flask app (`http://eflp_app:5000`)
3. Flask app -> Neo4j for case metadata
4. Parsed uploads and live syslog -> Elasticsearch `eflp-rag`
5. Chat question -> Elasticsearch retrieval -> Ollama `granite4.1:8b`
6. Optional export buttons -> Elasticsearch / InfluxDB

## Quick Start (Docker Compose)


```bash
cd eflp
docker compose up -d --build
```

On the first start, `ollama-model` downloads `granite4.1:8b` before `eflp_app` starts. The official Ollama tag is about 5.3 GB, so first startup can take several minutes and needs enough free memory and disk space. An exited `ollama-model` container with exit code `0` is expected after the pull completes.

Monitor first startup:

```bash
docker compose logs -f ollama-model
docker compose ps
```

Open:

- `http://localhost:8080` (redirects to HTTPS)
- `https://localhost:8443` (nginx UI; accept the local self-signed certificate)
- `http://localhost:5000` (direct app)
- `https://localhost:8443/chat` or `http://localhost:5000/chat` (Granite RAG chat)
- Neo4j browser: `http://localhost:7474` (default auth in compose is `neo4j/testuser`)
- Elasticsearch API: `http://localhost:9200`
- InfluxDB API: `http://localhost:8086`
- Ollama API: `http://localhost:11434`
- UDP syslog target: `localhost:5514`

Container-internal endpoints used by `eflp_app`:

- Neo4j: `bolt://neo4j:7687`
- Elasticsearch: `http://elasticsearch:9200`
- InfluxDB: `http://influxdb:8086`
- Ollama: `http://ollama:11434`

Verify local services:

```bash
curl http://localhost:9200/_cluster/health
curl http://localhost:8086/ping
curl http://localhost:11434/api/tags
curl http://localhost:9200/eflp-rag/_count
```

Inspect exported InfluxDB measurements:

```bash
curl -G http://localhost:8086/query \
  --data-urlencode 'db=eflp' \
  --data-urlencode 'q=SHOW MEASUREMENTS'
```

The named volumes `neo4j_data`, `elasticsearch_data`, `influxdb_data`, `ollama_data`, and `eflp_uploads` preserve local state across normal `docker compose down` and restart cycles. `docker compose down -v` intentionally deletes that data.

### Configuration

The Compose defaults can be overridden in `docker-compose.yml` or with an override file:

- `ELASTICSEARCH_URL=http://elasticsearch:9200`
- `ELASTICSEARCH_INDEX=eflp-rag`
- `INFLUXDB_URL=http://influxdb:8086`
- `INFLUXDB_DATABASE=eflp`
- `OLLAMA_URL=http://ollama:11434`
- `OLLAMA_MODEL=granite4.1:8b`
- `OLLAMA_TIMEOUT_SECONDS=300`
- `OLLAMA_NUM_CTX=8192`
- `EFLP_RAG_ENABLED=true`
- `EFLP_RAG_TOP_K=8`
- `EFLP_RAG_CONTEXT_CHARS=16000`
- `EFLP_RAG_QUEUE_SIZE=10000`


## Supported Input Types

Upload accepts:

- `.log`
- `.txt`
- `.csv`
- `.tsv`
- `.tgz`
- `.tar.gz`

CSV/TSV inputs are read directly into records; other formats are parsed by vendor-specific parsers.
