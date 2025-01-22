import re
from parsers.base_parser import BaseParser

class CheckpointParser(BaseParser):
    SYSLOG_REGEX = re.compile(
        r'^<(?P<priority>\d+)>(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<payload>.*)$'
    )
    NAMEVAL_REGEX = re.compile(r'(?P<key>\w+)\s*[:=]\s*"?(?P<value>[^"]+)"?;?')
    LEEF_REGEX = re.compile(r'^LEEF:2\.0\|Check Point\|.*$')

    NUMERIC_FIELDS=['s_port','service','proto','sid','srcport','dstport']

    def parse(self,file_path):
        data=[]
        with open(file_path,'r') as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                sys_m=self.SYSLOG_REGEX.match(line)
                if sys_m:
                    rec=self._parse_syslog_line(sys_m)
                    if rec:
                        data.append(rec)
                    continue
        return data

    def _parse_syslog_line(self,matchobj):
        prio=matchobj.group('priority')
        month=matchobj.group('month')
        day=matchobj.group('day')
        timestr=matchobj.group('time')
        host=matchobj.group('host')
        payload=matchobj.group('payload')
        final_ts=f"{month} {day} {timestr}"
        kv_pairs=self.NAMEVAL_REGEX.findall(payload)
        kv_dict={}
        for k,v in kv_pairs:
            kv_dict[k.lower()]=v.strip()
        for nf in self.NUMERIC_FIELDS:
            if nf in kv_dict:
                kv_dict[nf]=self.to_int(kv_dict[nf])
        srcip=kv_dict.get('src','')
        dstip=kv_dict.get('dst','')
        severity='INFO'
        if int(prio)<5:
            severity='HIGH'
        rec=self.build_record(
            timestamp=final_ts,
            severity=severity,
            host=host,
            srcip=srcip,
            dstip=dstip,
            message=payload,
            raw_fields=kv_dict
        )
        return rec

    def get_elasticsearch_mapping(self):
        return {
            "mappings": {
                "properties": {
                    "timestamp":     {"type":"date"},
                    "severity":      {"type":"keyword"},
                    "severity_int":  {"type":"integer"},
                    "host":          {"type":"keyword"},
                    "srcip":         {"type":"ip"},
                    "dstip":         {"type":"ip"},
                    "srcport":       {"type":"integer"},
                    "dstport":       {"type":"integer"},
                    "sid":           {"type":"long"},
                    "message":       {"type":"text"},
                    "raw_fields":    {"type":"object","enabled":True}
                }
            }
        }
