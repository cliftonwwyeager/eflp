import re
from parsers.base_parser import BaseParser

class WatchguardParser(BaseParser):
    def parse(self, file_path):
        records = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                tokens = line.split()
                if len(tokens) < 10:
                    continue
                raw_timestamp = tokens[0] + " " + tokens[1]
                timestamp = self.to_iso(raw_timestamp, default=raw_timestamp)
                member = tokens[2]
                action = tokens[3]
                srcip = tokens[4]
                dstip = tokens[5]
                service = tokens[6]
                src_port = tokens[7]
                dst_port = tokens[8]
                additional = " ".join(tokens[9:])
                kv_pairs = re.findall(r'(\w+)=(".*?"|\S+)', additional)
                kv_dict = {}
                for key, val in kv_pairs:
                    kv_dict[key.lower()] = val.strip('"')
                if action.lower() in ["deny", "blocked"]:
                    severity = "HIGH"
                else:
                    severity = "INFO"
                if "rc" in kv_dict and kv_dict["rc"] != "100":
                    severity = "HIGH"
                record = self.build_record(
                    timestamp=timestamp,
                    severity=severity,
                    host=member,
                    srcip=srcip,
                    dstip=dstip,
                    srcport=self.to_int(src_port),
                    dstport=self.to_int(dst_port),
                    message=line,
                    raw_fields=kv_dict
                )
                record['severity_int'] = self._severity_to_int(severity)
                records.append(record)
        return records

    def _severity_to_int(self, severity_str):
        mapping = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'INFO': 5}
        return mapping.get(severity_str.upper(), 5)

    def get_elasticsearch_mapping(self):
        return {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "severity": {"type": "keyword"},
                    "severity_int": {"type": "integer"},
                    "host": {"type": "keyword"},
                    "srcip": {"type": "ip"},
                    "dstip": {"type": "ip"},
                    "srcport": {"type": "integer"},
                    "dstport": {"type": "integer"},
                    "message": {"type": "text"},
                    "raw_fields": {"type": "object", "enabled": True}
                }
            }
        }
