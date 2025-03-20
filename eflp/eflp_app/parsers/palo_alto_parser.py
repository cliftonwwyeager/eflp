import re
import csv
from parsers.base_parser import BaseParser

class PaloAltoParser(BaseParser):
    SYSLOG_REGEX = re.compile(r'^<(?P<priority>\d+)>\S+\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<payload>.*)$')

    def parse(self, file_path):
        records = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = self.SYSLOG_REGEX.match(line)
                if not match:
                    continue
                priority = match.group('priority')
                sys_ts = match.group('timestamp')
                sys_host = match.group('host')
                payload = match.group('payload')
                try:
                    fields = next(csv.reader([payload]))
                except Exception:
                    continue
                fields = [field.strip() for field in fields]
                if len(fields) < 4:
                    continue
                event_time = fields[0] if fields[0] else sys_ts
                palo_type = fields[2].upper() if len(fields) > 2 else ""
                action = fields[3].lower() if len(fields) > 3 else ""
                severity = "HIGH" if action in ("deny", "drop") else "INFO"
                if len(fields) >= 10:
                    src_zone = fields[4]
                    dst_zone = fields[5]
                    src_ip = fields[6]
                    dst_ip = fields[7]
                    src_port = fields[8]
                    dst_port = fields[9]
                    message = (
                        f"Traffic from {src_ip}:{src_port} ({src_zone}) "
                        f"to {dst_ip}:{dst_port} ({dst_zone}) action: {fields[3]}"
                    )
                
                else:
                    message = payload
                raw_fields = {f"field_{i}": value for i, value in enumerate(fields)}
                record = self.build_record(
                    timestamp=event_time,
                    severity=severity,
                    host=sys_host,
                    message=message,
                    raw_fields=raw_fields
                )
                
                try:
                    record['syslog_priority'] = int(priority)
                except ValueError:
                    record['syslog_priority'] = priority

                record['syslog_timestamp'] = sys_ts
                record['syslog_host'] = sys_host
                record['palo_type'] = palo_type
                record['palo_action'] = action
                record['severity_int'] = self._severity_to_int(severity)

                records.append(record)
        return records

    def _severity_to_int(self, severity_str):
        mapping = {
            'CRITICAL': 1,
            'HIGH': 2,
            'MEDIUM': 3,
            'LOW': 4,
        }
        return mapping.get(severity_str.upper(), 5)

    def get_elasticsearch_mapping(self):
        return {
            "mappings": {
                "properties": {
                    "timestamp":       {"type": "date"},
                    "severity":        {"type": "keyword"},
                    "severity_int":    {"type": "integer"},
                    "host":            {"type": "keyword"},
                    "message":         {"type": "text"},
                    "syslog_priority": {"type": "integer"},
                    "syslog_timestamp": {"type": "keyword"},
                    "syslog_host":     {"type": "keyword"},
                    "palo_type":       {"type": "keyword"},
                    "palo_action":     {"type": "keyword"},
                    "raw_fields":      {"type": "object", "enabled": True}
                }
            }
        }
