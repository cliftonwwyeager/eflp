import re
import csv
from parsers.base_parser import BaseParser

class PaloAltoParser(BaseParser):
    SYSLOG_REGEX = re.compile(r'^<(?P<priority>\d+)>\S*\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<payload>.*)$')

    def parse(self, file_path):
        data = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = self.SYSLOG_REGEX.match(line)
                if not m:
                    continue
                priority = m.group('priority')
                sys_ts = m.group('timestamp')
                sys_host = m.group('host')
                payload = m.group('payload')
                try:
                    reader = csv.reader([payload])
                    fields = next(reader)
                except Exception:
                    continue
                fields = [field.strip() for field in fields]
                if len(fields) < 4:
                    continue
                raw_type = fields[3].strip().upper()
                if raw_type == 'THREAT':
                    severity = 'HIGH'
                elif raw_type == 'SYSTEM':
                    severity = 'MEDIUM'
                else:
                    severity = 'INFO'
                event_time = fields[1].strip() if len(fields) > 1 and fields[1].strip() else sys_ts
                message_parts = []
                if len(fields) >= 5:
                    message_parts.append(f"Host: {fields[4]}")
                if len(fields) >= 7:
                    message_parts.append(f"Extra: {fields[6]}")
                message = " | ".join(message_parts) if message_parts else payload
                raw_fields = {f"field_{i}": fields[i] for i in range(len(fields))}
                rec = self.build_record(
                    timestamp=event_time,
                    severity=severity,
                    host=sys_host,
                    message=message,
                    raw_fields=raw_fields
                )
                try:
                    rec['syslog_priority'] = int(priority)
                except ValueError:
                    rec['syslog_priority'] = priority
                rec['syslog_timestamp'] = sys_ts
                rec['syslog_host'] = sys_host
                rec['raw_pan_type'] = raw_type
                if 'severity' in rec:
                    rec['severity_int'] = self._severity_to_int(rec['severity'])
                data.append(rec)
        return data

    def _severity_to_int(self, severity_str):
        sev = severity_str.upper()
        if sev == 'CRITICAL':
            return 1
        if sev == 'HIGH':
            return 2
        if sev == 'MEDIUM':
            return 3
        if sev == 'LOW':
            return 4
        return 5

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
                    "raw_pan_type":    {"type": "keyword"},
                    "raw_fields":      {"type": "object", "enabled": True}
                }
            }
        }
