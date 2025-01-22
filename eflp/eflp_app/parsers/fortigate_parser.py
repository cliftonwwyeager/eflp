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
                priority = m.group('priority')
                payload = m.group('payload')
                kv_pairs = self.KV_REGEX.findall(payload)
                kv_dict = {}
                for k, v in kv_pairs:
                    kv_dict[k.lower()] = v
                level_str = kv_dict.get('level','').lower()
                severity = self.LEVEL_TO_SEVERITY.get(level_str, 'INFO')
                final_time = (kv_dict.get('date','') + ' ' + kv_dict.get('time','')).strip()
                src_port = self.to_int(kv_dict.get('srcport'))
                dst_port = self.to_int(kv_dict.get('dstport'))
                session_id = self.to_int(kv_dict.get('sessionid'))
                sentbyte = self.to_int(kv_dict.get('sentbyte'))
                rcvdbyte = self.to_int(kv_dict.get('rcvdbyte'))
                sentpkt = self.to_int(kv_dict.get('sentpkt'))
                rcvdpkt = self.to_int(kv_dict.get('rcvdpkt'))
                rec = self.build_record(
                    timestamp=final_time,
                    severity=severity,
                    srcip=kv_dict.get('srcip',''),
                    dstip=kv_dict.get('dstip',''),
                    srcport=src_port,
                    dstport=dst_port,
                    sessionid=session_id,
                    sentbyte=sentbyte,
                    rcvdbyte=rcvdbyte,
                    sentpkt=sentpkt,
                    rcvdpkt=rcvdpkt,
                    raw_fields=kv_dict,
                    message=kv_dict.get('msg','')
                )
                data.append(rec)
        return data

    def get_elasticsearch_mapping(self):
        return {
            "mappings": {
                "properties": {
                    "timestamp":     {"type": "date"},
                    "severity":      {"type": "keyword"},
                    "severity_int":  {"type": "integer"},
                    "srcip":         {"type": "ip"},
                    "dstip":         {"type": "ip"},
                    "srcport":       {"type": "integer"},
                    "dstport":       {"type": "integer"},
                    "sessionid":     {"type": "long"},
                    "sentbyte":      {"type": "long"},
                    "rcvdbyte":      {"type": "long"},
                    "sentpkt":       {"type": "long"},
                    "rcvdpkt":       {"type": "long"},
                    "raw_fields":    {"type": "object", "enabled":True},
                    "message":       {"type": "text"}
                }
            }
        }
