import re
from parsers.base_parser import BaseParser

class SonicwallParser(BaseParser):
    KV_REGEX = re.compile(r'(?P<key>\w+)\s*=\s*"?(?P<value>[^"]+)"?')

    def parse(self, file_path):
        records = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                kv_dict = self._parse_key_values(line)
                src_port = self.to_int(kv_dict.get('sport'))
                dst_port = self.to_int(kv_dict.get('dport'))
                sess_id = self.to_int(kv_dict.get('sessionid'))
                severity = self._determine_severity(kv_dict.get('pri'))
                record = self.build_record(
                    timestamp=kv_dict.get('time', ''),
                    severity=severity,
                    srcip=kv_dict.get('src', ''),
                    dstip=kv_dict.get('dst', ''),
                    srcport=src_port,
                    dstport=dst_port,
                    sessionid=sess_id,
                    raw_fields=kv_dict,
                    message=kv_dict.get('msg', '')
                )
                record['severity_int'] = self._severity_to_int(severity)
                records.append(record)
        return records

    def _parse_key_values(self, line):
        kv_pairs = self.KV_REGEX.findall(line)
        return {k.lower(): v.strip() for k, v in kv_pairs}

    def _determine_severity(self, pri_val):
        severity = 'INFO'
        if pri_val is not None:
            try:
                p = int(pri_val)
                if p <= 2:
                    severity = 'CRITICAL'
                elif p == 3:
                    severity = 'HIGH'
                elif p == 4:
                    severity = 'MEDIUM'
                elif p == 5:
                    severity = 'LOW'
                else:
                    severity = 'INFO'
            except ValueError:
                severity = 'INFO'
        return severity

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
                    "raw_fields":   {"type": "object", "enabled": True},
                    "message":      {"type": "text"}
                }
            }
        }
