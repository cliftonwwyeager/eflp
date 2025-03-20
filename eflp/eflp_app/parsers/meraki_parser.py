import re
from parsers.base_parser import BaseParser
from dateutil import parser as date_parser
from datetime import datetime

class MerakiParser(BaseParser):
    def parse(self, file_path):
        records = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                tokens = line.split()
                device_id, event_type, timestamp = '', '', ''
                severity = 'INFO'
                if tokens and self._is_numeric(tokens[0]):
                    timestamp = self._parse_timestamp(tokens.pop(0))
                if tokens and '=' not in tokens[0]:
                    device_id = tokens.pop(0)
                if tokens and '=' not in tokens[0]:
                    event_type = tokens.pop(0)
                log_entry, leftover = self._parse_tokens(tokens)
                if device_id:
                    log_entry['device_id'] = device_id
                if event_type:
                    log_entry['event_type'] = event_type
                if leftover and 'message' not in log_entry:
                    log_entry['message'] = ' '.join(leftover).strip()
                if 'timestamp' in log_entry:
                    try:
                        parsed_ts = date_parser.parse(log_entry['timestamp'])
                        timestamp = parsed_ts.isoformat()
                        log_entry['timestamp'] = timestamp
                    except Exception:
                        timestamp = log_entry['timestamp']
                if not timestamp:
                    timestamp = log_entry.get('timestamp', '')
                severity = self._parse_severity(log_entry.get('priority'))
                srcip, srcport = self._parse_ip_port(log_entry.get('src'))
                dstip, dstport = self._parse_ip_port(log_entry.get('dst'))
                for field in ['sport', 'srcport']:
                    if field in log_entry:
                        srcport = self.to_int(log_entry[field])
                for field in ['dport', 'dstport']:
                    if field in log_entry:
                        dstport = self.to_int(log_entry[field])
                host = device_id or log_entry.get('device_id', '')
                message = log_entry.get('message', line)
                record = self.build_record(
                    timestamp=timestamp,
                    severity=severity,
                    host=host,
                    srcip=srcip,
                    dstip=dstip,
                    srcport=srcport,
                    dstport=dstport,
                    message=message,
                    raw_fields=log_entry
                )
                record['severity_int'] = self._severity_to_int(severity)
                records.append(record)
        return records

    def _is_numeric(self, token):
        try:
            float(token)
            return True
        except ValueError:
            return False

    def _parse_timestamp(self, token):
        try:
            ts_float = float(token)
            return datetime.fromtimestamp(ts_float).isoformat()
        except Exception:
            return token

    def _parse_tokens(self, tokens):
        log_entry = {}
        leftover = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if '=' in token:
                key, value = token.split('=', 1)
                log_entry[key.strip().lower()] = value.strip().strip('"')
                i += 1
            elif token.endswith(':') and i < len(tokens) - 1:
                key = token[:-1].lower()
                j = i + 1
                value_tokens = []
                while j < len(tokens) and '=' not in tokens[j]:
                    value_tokens.append(tokens[j])
                    j += 1
                log_entry[key] = ' '.join(value_tokens).strip()
                i = j
            else:
                leftover.append(token)
                i += 1
        return log_entry, leftover

    def _parse_severity(self, priority_value):
        if priority_value:
            try:
                p = int(priority_value)
                if p == 1:
                    return 'HIGH'
                elif p == 2:
                    return 'MEDIUM'
                elif p == 3:
                    return 'LOW'
            except Exception:
                return 'INFO'
        return 'INFO'

    def _parse_ip_port(self, value):
        ip = ''
        port = None
        if value:
            if ':' in value:
                parts = value.split(':', 1)
                ip = parts[0]
                port = self.to_int(parts[1])
            else:
                ip = value
        return ip, port

    def _severity_to_int(self, severity_str):
        mapping = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'INFO': 5}
        return mapping.get(severity_str.upper(), 5)

    def get_elasticsearch_mapping(self):
        return {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "severity":  {"type": "keyword"},
                    "severity_int": {"type": "integer"},
                    "host":      {"type": "keyword"},
                    "srcip":     {"type": "ip"},
                    "dstip":     {"type": "ip"},
                    "srcport":   {"type": "integer"},
                    "dstport":   {"type": "integer"},
                    "message":   {"type": "text"},
                    "raw_fields": {"type": "object", "enabled": True}
                }
            }
        }
