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
        data = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = self.SYSLOG_REGEX.match(line)
                if not m:
                    continue
                payload = m.group('payload')
                kv_pairs = self.KV_REGEX.findall(payload)
                kv_dict = {}
                for k, v in kv_pairs:
                    kv_dict[k.lower()] = v.strip()
                level_str = kv_dict.get('level', '').lower()
                severity = self.LEVEL_TO_SEVERITY.get(level_str, 'INFO')
                timestamp = (kv_dict.get('date', '') + ' ' + kv_dict.get('time', '')).strip()
                for field in ['srcport', 'dstport', 'sessionid', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt']:
                    if field in kv_dict:
                        kv_dict[field] = self.to_int(kv_dict[field])
                srcip = kv_dict.get('srcip', '')
                dstip = kv_dict.get('dstip', '')
                rec = self.build_record(
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
                if rec and 'severity' in rec:
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
