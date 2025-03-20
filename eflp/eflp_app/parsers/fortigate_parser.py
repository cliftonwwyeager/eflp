import re
from parsers.base_parser import BaseParser

class FortigateParser(BaseParser):
    SYSLOG_REGEX = re.compile(r'^<(?P<priority>\d+)>(?P<payload>.*)$')
    KV_REGEX = re.compile(r'(?P<key>\w+)\s*=\s*"?(?P<value>[^"]+)"?')
    LEVEL_TO_SEVERITY = {
        'emergency': 'CRITICAL',
        'alert': 'CRITICAL',
        'critical': 'CRITICAL',
        'error': 'HIGH',
        'warning': 'MEDIUM',
        'notice': 'LOW',
        'information': 'INFO',
        'debug': 'INFO'
    }

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
                payload = match.group('payload')
                kv_dict = self._parse_key_values(payload)
                level_str = kv_dict.get('level', '').lower()
                severity = self.LEVEL_TO_SEVERITY.get(level_str, 'INFO')
                timestamp = f"{kv_dict.get('date', '').strip()} {kv_dict.get('time', '').strip()}".strip()
                for field in ['srcport', 'dstport', 'sessionid', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt']:
                    if field in kv_dict:
                        kv_dict[field] = self.to_int(kv_dict[field])
                srcip = kv_dict.get('srcip', '')
                dstip = kv_dict.get('dstip', '')
                record = self.build_record(
                    timestamp=timestamp,
                    severity=severity,
                    srcip=srcip,
                    dstip=dstip,
                    srcport=kv_dict.get('srcport'),
                    dstport=kv_dict.get('dstport'),
                    sessionid=kv_dict.get('sessionid'),
                    sentbyte=kv_dict.get('sentbyte'),
                    rcvdbyte=kv_dict.get('rcvdbyte'),
                    sentpkt=kv_dict.get('sentpkt'),
                    rcvdpkt=kv_dict.get('rcvdpkt'),
                    raw_fields=kv_dict,
                    message=kv_dict.get('msg', '')
                )
                record['severity_int'] = self._severity_to_int(severity)
                records.append(record)
        return records

    def _parse_key_values(self, payload):
        kv_pairs = self.KV_REGEX.findall(payload)
        return {k.lower(): v.strip() for k, v in kv_pairs}

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
                    "srcip":        {"type": "ip"},
                    "dstip":        {"type": "ip"},
                    "srcport":      {"type": "integer"},
                    "dstport":      {"type": "integer"},
                    "sessionid":    {"type": "long"},
                    "sentbyte":     {"type": "long"},
                    "rcvdbyte":     {"type": "long"},
                    "sentpkt":      {"type": "long"},
                    "rcvdpkt":      {"type": "long"},
                    "raw_fields":   {"type": "object", "enabled": True},
                    "message":      {"type": "text"}
                }
            }
        }
