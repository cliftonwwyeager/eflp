import re
from parsers.base_parser import BaseParser

class CiscoFTDParser(BaseParser):
    SYSLOG_REGEX = re.compile(r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<payload>.*)$')
    NAMEVAL_REGEX = re.compile(r'(?P<key>\w+)\s*:\s*"?(?P<value>[^"]+)"?(?=,|$)')
    NUMERIC_FIELDS = ['priority', 'gid', 'sid', 'revision', 'srcport', 'dstport',
                      'initiatorpackets', 'responderpackets', 'initiatorbytes', 'responderbytes']

    def parse(self, file_path):
        records = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = self.SYSLOG_REGEX.match(line)
                if not m:
                    continue
                timestamp = f"{m.group('month')} {m.group('day')} {m.group('time')}"
                host = m.group('host')
                payload = m.group('payload')
                kv_dict = self._parse_key_values(payload)
                severity = self._parse_severity(kv_dict.get('priority'))
                srcip = kv_dict.get('srcip', kv_dict.get('src', ''))
                dstip = kv_dict.get('dstip', kv_dict.get('dst', ''))
                record = self.build_record(
                    timestamp=timestamp,
                    severity=severity,
                    host=host,
                    srcip=srcip,
                    dstip=dstip,
                    srcport=kv_dict.get('srcport'),
                    dstport=kv_dict.get('dstport'),
                    message=payload,
                    raw_fields=kv_dict
                )
                record['severity_int'] = self._severity_to_int(severity)
                records.append(record)
        return records

    def _parse_key_values(self, payload):
        kv_pairs = self.NAMEVAL_REGEX.findall(payload)
        kv_dict = {k.lower(): v.strip() for k, v in kv_pairs}
        for field in self.NUMERIC_FIELDS:
            if field in kv_dict:
                kv_dict[field] = self.to_int(kv_dict[field])
        return kv_dict

    def _parse_severity(self, priority_val):
        try:
            if priority_val is not None:
                p = int(priority_val)
                if p == 1:
                    return 'HIGH'
                elif p == 2:
                    return 'MEDIUM'
                elif p == 3:
                    return 'LOW'
        except (TypeError, ValueError):
            pass
        return 'INFO'

    def _severity_to_int(self, severity_str):
        mapping = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'INFO': 5}
        return mapping.get(severity_str.upper(), 5)

    def get_elasticsearch_mapping(self):
        return {
            "mappings": {
                "properties": {
                    "timestamp":    {"type": "date"},
                    "severity":     {"type": "keyword"},
                    "severity_int": {"type": "integer"},
                    "host":         {"type": "keyword"},
                    "srcip":        {"type": "ip"},
                    "dstip":        {"type": "ip"},
                    "srcport":      {"type": "integer"},
                    "dstport":      {"type": "integer"},
                    "message":      {"type": "text"},
                    "raw_fields":   {"type": "object", "enabled": True}
                }
            }
        }
