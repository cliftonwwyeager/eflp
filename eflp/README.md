# EFLP v0.0.4

A simple Flask app that stores firewall log “cases” in Neo4j, parses logs with vendor-specific parsers, displays severity charts, and exports logs to Elasticsearch. Runs on over ssl/tls on **port 8443** 

## Features

1. **Neo4j Case Storage**  
   - Each uploaded log file creates a new “case” node in Neo4j with a unique UUID.  
   - We keep only label, vendor, and local file path in Neo4j.

2. **Vendor-Specific Parsing**  
   - Five built-in parsers: Palo Alto, Fortigate, SonicWall, Cisco FTD, Check Point.  
   - Each parser extracts integer fields (ports, session IDs) and returns consistent fields (`severity`, `timestamp`, etc.).

3. **Severity Chart**  
   - For each case, we generate a bar chart of log severities using `matplotlib` and embed it as a Base64-encoded image in the page.

4. **Elasticsearch Export**  
   - A form allows specifying ES URL, index name, and optional username/password.  
   - On export, we create an index with vendor-specific integer mappings,  and bulk-upload logs.

5. **Runs Over Port 8443**  
   - By default, the app runs `app.run(host="0.0.0.0", port=8443, debug=True)` in Python code.  
   - In production, you likely run behind an **Nginx** reverse proxy for TLS, or you can configure built-in SSL context.

---

## Requirements

- **Docker** and (optionally) **Docker Compose**  
- A **Neo4j** instance or container accessible at `$NEO4J_URI` (default `bolt://neo4j:7687`)  
- The environment variables `NEO4J_USER` and `NEO4J_PASSWORD` (default `neo4j` / `testuser`)

---


## Docker Build and Run

cd to eflp directory, then run 

docker-compose build
docker-compose up -d