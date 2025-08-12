# EFLP v0.1.0

A Flask application that parses firewall traffic logs by selected vendor. The app features a modern, dark-themed UI and supports vendor-specific parsing, log severity visualization, and multiple export options (Elasticsearch, InfluxDB, and CSV). The application is served over SSL/TLS on port 8443.

## Features

1. **Vendor-Specific Parsing**  
   - Eleven built-in parsers: Palo Alto, Fortigate, SonicWall, Cisco FTD, Cisco Meraki, CheckPoint, Unifi, Juniper, Watchguard, Sophos UTM/XGS, and Netscaler.  
   - Each parser extracts integer fields (ports, session IDs) and returns consistent fields (`severity`, `timestamp`, etc.).

2. **Severity Chart**  
   - For each case, a bar chart is generated using Plotly that displays the count of logs by severity, and event distribution over a 24 hour period.
   - The chart is embedded directly in the case view for quick visual analysis.

3. **Elasticsearch Export**  
   - A form allows specifying ES URL, index name, and optional username/password.  
   - On export, we create an index with vendor-specific integer mappings, and bulk-upload logs.

4. **InfluxDB Export**
   - Parsed logs can be exported to InfluxDB by providing the InfluxDB URL, database name, and credentials.
   - Logs are written as InfluxDB points with appropriate tags and fields.

5. **CSV Export**
   - The application supports exporting parsed logs to a CSV file, allowing for easy download and further analysis.
---

## Requirements

- **Docker** , **Docker Compose**  

## Docker Build and Run

cd to eflp/eflp_app directory, then run 
```
docker-compose build
docker-compose up -d

