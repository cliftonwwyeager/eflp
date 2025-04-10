import re
from parsers.base_parser import BaseParser
from dateutil import parser as date_parser

class SophosUTMParser(BaseParser):
    SYSLOG_REGEX = re.compile(
        r'^<(?P<priority>\d+)>(?P<month>\w{3})\s+(?P<day>\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sophosutm:\s+(?P<payload>.*)$'
     )
    KV_REGEX = re.compile(r'(?P<key>\w+)=(".*?"|\S+)')
    
    def parse(self, file_path):
        records = []
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = self.SYSLOG_REGEX.match(line)
                if m:
                    raw_timestamp = f"{m.group('month')} {m.group('day')} {m.group('time')}"
                    timestamp = self.to_iso(raw_timestamp, default=raw_timestamp)
                    host = m.group("host")
                    payload = m.group("payload")
                else:
                    timestamp = ""
                    host = ""
                    payload = line
                kv_pairs = self.KV_REGEX.findall(payload)
                kv_dict = {}
                for key, val in kv_pairs:
                    if val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                    kv_dict[key.lower()] = val
                srcip    = kv_dict.get("src", "")
                dstip    = kv_dict.get("dst", "")
                srcport  = self.to_int(kv_dict.get("sport"))
                dstport  = self.to_int(kv_dict.get("dport"))
                protocol = kv_dict.get("proto", "")
                action   = kv_dict.get("action", "").upper()
                severity = "HIGH" if action in ["DENY", "BLOCK"] else "INFO"
                message = kv_dict.get("msg", payload)
                record = self.build_record(
                    timestamp=timestamp,
                    severity=severity,
                    host=host,
                    srcip=srcip,
                    dstip=dstip,
                    srcport=srcport,
                    dstport=dstport,
                    protocol=protocol,
                    action=action,
                    message=message,
                    raw_fields=kv_dict
                )
                record['severity_int'] = self._severity_to_int(severity)
                records.append(record)
        return records

    def _severity_to_int(self, severity_str):
        mapping = {
            'CRITICAL': 1,
            'HIGH': 2,
            'MEDIUM': 3,
            'LOW': 4,
            'INFO': 5
        }
        return mapping.get(severity_str.upper(), 5)

    def get_elasticsearch_mapping(self):
        return {
            "mappings": {
                "properties": {
                    "timestamp":   {"type": "date"},
                    "severity":    {"type": "keyword"},
                    "severity_int": {"type": "integer"},
                    "host":        {"type": "keyword"},
                    "srcip":       {"type": "ip"},
                    "dstip":       {"type": "ip"},
                    "srcport":     {"type": "integer"},
                    "dstport":     {"type": "integer"},
                    "protocol":    {"type": "keyword"},
                    "action":      {"type": "keyword"},
                    "message":     {"type": "text"},
                    "raw_fields":  {"type": "object", "enabled": True}
                }
            }
        }