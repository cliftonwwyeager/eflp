# EFLP v0.0.5

A flask application using Neo4j for session/user management, parses firewall logs by selected vendor, uses matpoltlib to create a bar graph displaying a count of parsed logs by severity, Elasticsearch integration. Application presented over ssl/tls on **port 8443** 

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

---

## Requirements

- **Docker** and (optionally) **Docker Compose**  

## Docker Build and Run

cd to eflp/eflp_app directory, then run 

docker-compose build
docker-compose up -d
