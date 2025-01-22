import re
from parsers.base_parser import BaseParser

class SonicwallParser(BaseParser):
    KV_REGEX = re.compile(r'(?P<key>\w+)\s*=\s*"?(?P<value>[^"]+)"?')

    def parse(self, file_path):
        data = []
        with open(file_path,'r') as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                kv_pairs=self.KV_REGEX.findall(line)
                kv_dict={}
                for k,v in kv_pairs:
                    kv_dict[k.lower()]=v
                src_port=self.to_int(kv_dict.get('sport'))
                dst_port=self.to_int(kv_dict.get('dport'))
                sess_id=self.to_int(kv_dict.get('sessionid'))
                severity='INFO'
                pri=kv_dict.get('pri','6')
                if pri=='3':
                    severity='HIGH'
                rec=self.build_record(
                    timestamp=kv_dict.get('time',''),
                    severity=severity,
                    srcip=kv_dict.get('src',''),
                    dstip=kv_dict.get('dst',''),
                    srcport=src_port,
                    dstport=dst_port,
                    sessionid=sess_id,
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
                    "raw_fields":    {"type": "object", "enabled":True},
                    "message":       {"type": "text"}
                }
            }
        }
