import re
from parsers.base_parser import BaseParser
from dateutil import parser as date_parser
from datetime import datetime

class MerakiParserOptimized(BaseParser):
    def parse(self, file_path):
        parsed_logs = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                tokens = line.split()
                device_id = ''
                event_type = ''
                timestamp = ''
                severity = 'INFO'
                if tokens and tokens[0].replace('.', '', 1).isdigit():
                    try:
                        ts_float = float(tokens[0])
                        timestamp = datetime.fromtimestamp(ts_float).isoformat()
                    except Exception:
                        timestamp = tokens[0]
                    tokens = tokens[1:]
                if tokens and '=' not in tokens[0]:
                    device_id = tokens[0]
                    tokens = tokens[1:]
                if tokens and '=' not in tokens[0]:
                    event_type = tokens[0]
                    tokens = tokens[1:]
                log_entry = {}
                leftover_words = []
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
                        leftover_words.append(token)
                        i += 1
                if device_id:
                    log_entry['device_id'] = device_id
                if event_type:
                    log_entry['event_type'] = event_type
                if leftover_words and 'message' not in log_entry:
                    log_entry['message'] = ' '.join(leftover_words).strip()
                if 'timestamp' in log_entry:
                    try:
                        log_entry['timestamp'] = date_parser.parse(log_entry['timestamp']).isoformat()
                        timestamp = log_entry['timestamp']
                    except Exception:
                        timestamp = log_entry['timestamp']
                if not timestamp:
                    timestamp = log_entry.get('timestamp', '')
                if 'priority' in log_entry:
                    try:
                        p = int(log_entry['priority'])
                        if p == 1:
                            severity = 'HIGH'
                        elif p == 2:
                            severity = 'MEDIUM'
                        elif p == 3:
                            severity = 'LOW'
                        else:
                            severity = 'INFO'
                    except Exception:
                        severity = 'INFO'
                else:
                    severity = 'INFO'
                srcip = ''
                dstip = ''
                srcport = None
                dstport = None
                if 'src' in log_entry:
                    src_val = log_entry['src']
                    if ':' in src_val:
                        parts = src_val.split(':', 1)
                        srcip = parts[0]
                        srcport = self.to_int(parts[1])
                    else:
                        srcip = src_val
                if 'dst' in log_entry:
                    dst_val = log_entry['dst']
                    if ':' in dst_val:
                        parts = dst_val.split(':', 1)
                        dstip = parts[0]
                        dstport = self.to_int(parts[1])
                    else:
                        dstip = dst_val
                if 'sport' in log_entry:
                    srcport = self.to_int(log_entry['sport'])
                if 'dport' in log_entry:
                    dstport = self.to_int(log_entry['dport'])
                if 'srcport' in log_entry:
                    srcport = self.to_int(log_entry['srcport'])
                if 'dstport' in log_entry:
                    dstport = self.to_int(log_entry['dstport'])
                host = device_id
                message = log_entry.get('message', line)
                rec = self.build_record(
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
                if rec and 'severity' in rec:
                    rec['severity_int'] = self._severity_to_int(rec['severity'])
                parsed_logs.append(rec)
        return parsed_logs

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
