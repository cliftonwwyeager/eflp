import re
from parsers.base_parser import BaseParser

class UnifiParserOptimized(BaseParser):
    SYSLOG_REGEX = re.compile(
        r'^<(?P<priority>\d+)>(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+):\s+(?P<payload>.*)$'
    )
    KV_REGEX = re.compile(r'(?P<key>\w+)=("?(?P<value>[^"\s]+)"?)')

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
                month = m.group('month')
                day = m.group('day')
                time_str = m.group('time')
                host = m.group('host')
                payload = m.group('payload')
                timestamp = f"{month} {day} {time_str}"
                payload = self._strip_prefix(payload)
                kv_pairs = self.KV_REGEX.findall(payload)
                kv_dict = {}
                for match in kv_pairs:
                    key = match[0].lower()
                    value = match[2].strip().strip('[]')
                    kv_dict[key] = value
                try:
                    prio_int = int(priority)
                    sev_code = prio_int % 8
                    if sev_code <= 2:
                        severity = 'CRITICAL'
                    elif sev_code == 3:
                        severity = 'HIGH'
                    elif sev_code == 4:
                        severity = 'MEDIUM'
                    elif sev_code == 5:
                        severity = 'LOW'
                    else:
                        severity = 'INFO'
                except ValueError:
                    severity = 'INFO'

                srcip = kv_dict.get('src', '')
                dstip = kv_dict.get('dst', '')
                protocol = kv_dict.get('protocol', '')
                spt = self.to_int(kv_dict.get('spt') or kv_dict.get('srcport'))
                dpt = self.to_int(kv_dict.get('dpt') or kv_dict.get('dstport'))
                action = kv_dict.get('action', '')
                rec = self.build_record(
                    timestamp=timestamp,
                    severity=severity,
                    host=host,
                    srcip=srcip,
                    dstip=dstip,
                    protocol=protocol,
                    srcport=spt,
                    dstport=dpt,
                    message=line,
                    raw_fields=kv_dict
                )
                rec['severity_int'] = self._severity_to_int(severity)
                data.append(rec)
        return data

    def _strip_prefix(self, payload):
        if payload.startswith('[') and ']' in payload:
            end = payload.find(']') + 1
            payload = payload[end:].strip()
        if payload.lower().startswith("firewall:"):
            payload = payload[len("firewall:"):].strip()
        return payload

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
                    "protocol":     {"type": "keyword"},
                    "srcport":      {"type": "integer"},
                    "dstport":      {"type": "integer"},
                    "message":      {"type": "text"},
                    "raw_fields":   {"type": "object", "enabled": True}
                }
            }
        }
