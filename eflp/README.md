# EFLP v0.0.6

A flask application that parses firewall logs by selected vendor, uses matpoltlib to create a bar graph displaying a count of parsed logs by severity, Elasticsearch integration. Application presented over ssl/tls on **port 8443** 

## Features

1. **Vendor-Specific Parsing**  
   - Five built-in parsers: Palo Alto, Fortigate, SonicWall, Cisco FTD, Check Point.  
   - Each parser extracts integer fields (ports, session IDs) and returns consistent fields (`severity`, `timestamp`, etc.).

2. **Severity Chart**  
   - For each case, we generate a bar chart of log severities using `matplotlib` and embed it as a Base64-encoded image in the page.

3. **Elasticsearch Export**  
   - A form allows specifying ES URL, index name, and optional username/password.  
   - On export, we create an index with vendor-specific integer mappings,  and bulk-upload logs.

---

## Requirements

- **Docker** and (optionally) **Docker Compose**  

## Docker Build and Run

cd to eflp/eflp_app directory, then run 

docker-compose build
docker-compose up -d
