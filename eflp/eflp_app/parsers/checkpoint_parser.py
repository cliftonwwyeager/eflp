import re
from parsers.base_parser import BaseParser
from datetime import datetime

class CheckpointParser(BaseParser):
    SYSLOG_REGEX = re.compile(r'^<(?P<priority>\d+)>(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<payload>.*)$')
    NAMEVAL_REGEX = re.compile(r'(?P<key>\w+)\s*[:=]\s*"?(?P<value>[^"]*?)"?(?=;|$)')
    LEEF_REGEX = re.compile(r'^LEEF:2\.0\|Check Point\|')
    NUMERIC_FIELDS = ['s_port', 'service', 'proto', 'sid', 'srcport', 'dstport']

    def parse(self, file_path):
        records = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                sys_match = self.SYSLOG_REGEX.match(line)
                if sys_match:
                    rec = self._parse_syslog_line(sys_match)
                    if rec:
                        records.append(rec)
                    continue
                if self.LEEF_REGEX.match(line):
                    rec = self._parse_leef_line(line)
                    if rec:
                        records.append(rec)
                    continue
        return records

    def _parse_syslog_line(self, matchobj):
        priority = matchobj.group('priority')
        month = matchobj.group('month')
        day = matchobj.group('day')
        time_str = matchobj.group('time')
        host = matchobj.group('host')
        payload = matchobj.group('payload')
        timestamp = f"{month} {day} {time_str}"
        kv_pairs = self.NAMEVAL_REGEX.findall(payload)
        kv_dict = {k.lower(): v.strip() for k, v in kv_pairs}
        for nf in self.NUMERIC_FIELDS:
            if nf in kv_dict:
                kv_dict[nf] = self.to_int(kv_dict[nf])
        srcip = kv_dict.get('src', kv_dict.get('srcip', ''))
        dstip = kv_dict.get('dst', kv_dict.get('dstip', ''))
        severity = self._calculate_severity(priority)
        record = self.build_record(
            timestamp=timestamp,
            severity=severity,
            host=host,
            srcip=srcip,
            dstip=dstip,
            message=payload,
            raw_fields=kv_dict
        )
        record['severity_int'] = self._severity_to_int(severity)
        return record

    def _parse_leef_line(self, line):
        parts = line.split('|', 5)
        if len(parts) < 6:
            return None
        kv_str = parts[5].strip()
        kv_dict = {}
        for key, val in re.findall(r'(\w+?)=(.*?)(?=\t|\s+\w+=|$)', kv_str):
            kv_dict[key.lower()] = val.strip()
        timestamp = ""
        if 'devtime' in kv_dict:
            ts_val = kv_dict['devtime']
            try:
                ts_float = float(ts_val)
                timestamp = datetime.fromtimestamp(ts_float).isoformat()
            except ValueError:
                timestamp = ts_val
        elif 'dhost' in kv_dict:
            timestamp = kv_dict.get('dhost', '')
        severity = 'INFO'
        if 'severity' in kv_dict:
            severity = kv_dict['severity'].upper()
        elif 'syslog_severity' in kv_dict:
            sev_text = kv_dict['syslog_severity'].lower()
            if sev_text in ['emergency', 'alert', 'critical']:
                severity = 'CRITICAL'
            elif sev_text in ['error']:
                severity = 'HIGH'
            elif sev_text in ['warning']:
                severity = 'MEDIUM'
            elif sev_text in ['notice']:
                severity = 'LOW'
        srcip = kv_dict.get('src', kv_dict.get('srcip', kv_dict.get('source ip', '')))
        dstip = kv_dict.get('dst', kv_dict.get('dstip', kv_dict.get('destination ip', '')))
        host = kv_dict.get('origin', '')
        record = self.build_record(
            timestamp=timestamp,
            severity=severity,
            host=host,
            srcip=srcip,
            dstip=dstip,
            message=line,
            raw_fields=kv_dict
        )
        record['severity_int'] = self._severity_to_int(severity)
        return record

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
                    "host":         {"type": "keyword"},
                    "srcip":        {"type": "ip"},
                    "dstip":        {"type": "ip"},
                    "srcport":      {"type": "integer"},
                    "dstport":      {"type": "integer"},
                    "sid":          {"type": "long"},
                    "message":      {"type": "text"},
                    "raw_fields":   {"type": "object", "enabled": True}
                }
            }
        }
