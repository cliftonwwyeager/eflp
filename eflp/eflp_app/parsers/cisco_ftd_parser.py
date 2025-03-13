import re
from parsers.base_parser import BaseParser

class CiscoFTDParserOptimized(BaseParser):
    SYSLOG_REGEX = re.compile(
        r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<payload>.*)$'
    )
    NAMEVAL_REGEX = re.compile(r'(?P<key>\w+)\s*:\s*"?(?P<value>[^"]+)"?(?=,|$)')
    NUMERIC_FIELDS = ['priority', 'gid', 'sid', 'revision', 'srcport', 'dstport',
                      'initiatorpackets', 'responderpackets', 'initiatorbytes', 'responderbytes']

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
                month = m.group('month')
                day = m.group('day')
                timestr = m.group('time')
                host = m.group('host')
                payload = m.group('payload')
                timestamp = f"{month} {day} {timestr}"
                kv_pairs = self.NAMEVAL_REGEX.findall(payload)
                kv_dict = {}
                for k, v in kv_pairs:
                    kv_dict[k.lower()] = v.strip()
                for nf in self.NUMERIC_FIELDS:
                    if nf in kv_dict:
                        kv_dict[nf] = self.to_int(kv_dict[nf])
                severity = 'INFO'
                prio_val = kv_dict.get('priority')
                if prio_val is not None:
                    try:
                        prio_int = int(prio_val)
                        if prio_int == 1:
                            severity = 'HIGH'
                        elif prio_int == 2:
                            severity = 'MEDIUM'
                        elif prio_int == 3:
                            severity = 'LOW'
                        else:
                            severity = 'INFO'
                    except (TypeError, ValueError):
                        severity = 'INFO'
                srcip = kv_dict.get('srcip', kv_dict.get('src', ''))
                dstip = kv_dict.get('dstip', kv_dict.get('dst', ''))
                srcport = kv_dict.get('srcport', None)
                dstport = kv_dict.get('dstport', None)
                rec = self.build_record(
                    timestamp=timestamp,
                    severity=severity,
                    host=host,
                    srcip=srcip,
                    dstip=dstip,
                    srcport=srcport,
                    dstport=dstport,
                    message=payload,
                    raw_fields=kv_dict
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
