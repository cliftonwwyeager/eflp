import re
from parsers.base_parser import BaseParser

class JuniperParser(BaseParser):
    def parse(self, file_path):
        records = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or "RT_FLOW" not in line:
                    continue
                if "SESSION_CREATE" in line:
                    event_type = "SESSION_CREATE"
                elif "SESSION_CLOSE" in line:
                    event_type = "SESSION_CLOSE"
                else:
                    event_type = "UNKNOWN"
                tokens = line.split()
                if line.startswith("<"):
                    try:
                        priority = tokens[0]
                        month = tokens[1]
                        day = tokens[2]
                        time_str = tokens[3]
                        host = tokens[4]
                        raw_timestamp = f"{month} {day} {time_str}"
                        timestamp = self.to_iso(raw_timestamp, default=raw_timestamp)
                        tokens = tokens[5:]
                    except Exception:
                        timestamp = ""
                        host = ""
                else:
                    timestamp = ""
                    host = ""
                message = " ".join(tokens)
                src_info = ""
                dst_info = ""
                if "->" in message:
                    parts = message.split("->")
                    src_info = parts[0].split()[-1]
                    dst_info = parts[1].split()[0]
                srcip = ""
                srcport = None
                dstip = ""
                dstport = None
                if "/" in src_info:
                    srcip, srcport_str = src_info.split("/", 1)
                    srcport = self.to_int(srcport_str)
                if "/" in dst_info:
                    dstip, dstport_str = dst_info.split("/", 1)
                    dstport = self.to_int(dstport_str)
                severity = "INFO" if event_type == "SESSION_CREATE" else "MEDIUM"
                record = self.build_record(
                    timestamp=timestamp,
                    severity=severity,
                    host=host,
                    srcip=srcip,
                    dstip=dstip,
                    srcport=srcport,
                    dstport=dstport,
                    message=line,
                    raw_fields={"event_type": event_type}
                )
                record['severity_int'] = self._severity_to_int(severity)
                records.append(record)
        return records

    def _severity_to_int(self, severity_str):
        mapping = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'INFO': 5}
        return mapping.get(severity_str.upper(), 5)

    def get_elasticsearch_mapping(self):
        return {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "severity": {"type": "keyword"},
                    "severity_int": {"type": "integer"},
                    "host": {"type": "keyword"},
                    "srcip": {"type": "ip"},
                    "dstip": {"type": "ip"},
                    "srcport": {"type": "integer"},
                    "dstport": {"type": "integer"},
                    "message": {"type": "text"},
                    "raw_fields": {"type": "object", "enabled": True}
                }
            }
        }
