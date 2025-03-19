import re
from parsers.base_parser import BaseParser

class UnifiParser(BaseParser):
    SYSLOG_REGEX = re.compile(r'^<(?P<priority>\d+)>(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+):\s+(?P<payload>.*)$')
    KV_REGEX = re.compile(r'(?P<key>\w+)=("?(?P<value>[^"\s]+)"?)')

    def parse(self, file_path):
        records = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                syslog_match = self.SYSLOG_REGEX.match(line)
                if not syslog_match:
                    continue
                parsed_line = self._parse_syslog_match(syslog_match)
                record = self.build_record(
                    timestamp=parsed_line['timestamp'],
                    severity=parsed_line['severity'],
                    host=parsed_line['host'],
                    srcip=parsed_line.get('srcip', ''),
                    dstip=parsed_line.get('dstip', ''),
                    protocol=parsed_line.get('protocol', ''),
                    srcport=parsed_line.get('srcport'),
                    dstport=parsed_line.get('dstport'),
                    message=line,
                    raw_fields=parsed_line['raw_fields']
                )
                record['severity_int'] = self._severity_to_int(parsed_line['severity'])
                records.append(record)
        return records

    def _parse_syslog_match(self, match):
        priority = match.group('priority')
        month = match.group('month')
        day = match.group('day')
        time_str = match.group('time')
        host = match.group('host')
        payload = match.group('payload')
        timestamp = f"{month} {day} {time_str}"
        payload = self._strip_prefix(payload)
        raw_fields = self._parse_kv_pairs(payload)
        severity = self._calculate_severity(priority)
        srcip = raw_fields.get('src', '')
        dstip = raw_fields.get('dst', '')
        protocol = raw_fields.get('protocol', '')
        srcport = self.to_int(raw_fields.get('spt') or raw_fields.get('srcport'))
        dstport = self.to_int(raw_fields.get('dpt') or raw_fields.get('dstport'))
        return {
            'timestamp': timestamp,
            'severity': severity,
            'host': host,
            'raw_fields': raw_fields,
            'srcip': srcip,
            'dstip': dstip,
            'protocol': protocol,
            'srcport': srcport,
            'dstport': dstport,
        }

    def _parse_kv_pairs(self, payload):
        kv_dict = {}
        for match in self.KV_REGEX.findall(payload):
            key = match[0].lower()
            value = match[2].strip().strip('[]')
            kv_dict[key] = value
        return kv_dict

    def _calculate_severity(self, priority_str):
        try:
            prio_int = int(priority_str)
            sev_code = prio_int % 8
            if sev_code <= 2:
                return 'CRITICAL'
            elif sev_code == 3:
                return 'HIGH'
            elif sev_code == 4:
                return 'MEDIUM'
            elif sev_code == 5:
                return 'LOW'
            else:
                return 'INFO'
        except ValueError:
            return 'INFO'

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
