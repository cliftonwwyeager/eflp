import re
from parsers.base_parser import BaseParser
from datetime import datetime

class CheckpointParser(BaseParser):
    SYSLOG_REGEX = re.compile(
        r'^<(?P<priority>\d+)>(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<payload>.*)$'
    )
    NAMEVAL_REGEX = re.compile(r'(?P<key>\w+)\s*[:=]\s*"?(?P<value>[^"]*?)"?(?=;|$)')
    LEEF_REGEX = re.compile(r'^LEEF:2\.0\|Check Point\|')
    NUMERIC_FIELDS = ['s_port', 'service', 'proto', 'sid', 'srcport', 'dstport']

    def parse(self, file_path):
        data = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                sys_match = self.SYSLOG_REGEX.match(line)
                if sys_match:
                    rec = self._parse_syslog_line(sys_match)
                    if rec:
                        data.append(rec)
                    continue
                if self.LEEF_REGEX.match(line):
                    rec = self._parse_leef_line(line)
                    if rec:
                        data.append(rec)
                    continue
        return data

    def _parse_syslog_line(self, matchobj):
        prio = matchobj.group('priority')
        month = matchobj.group('month')
        day = matchobj.group('day')
        timestr = matchobj.group('time')
        host = matchobj.group('host')
        payload = matchobj.group('payload')
        timestamp = f"{month} {day} {timestr}"
        kv_pairs = self.NAMEVAL_REGEX.findall(payload)
        kv_dict = {}
        for k, v in kv_pairs:
            kv_dict[k.lower()] = v.strip()
        for nf in self.NUMERIC_FIELDS:
            if nf in kv_dict:
                kv_dict[nf] = self.to_int(kv_dict[nf])
        srcip = kv_dict.get('src', kv_dict.get('srcip', ''))
        dstip = kv_dict.get('dst', kv_dict.get('dstip', ''))
        severity = 'INFO'
        try:
            prio_int = int(prio)
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
            pass
        rec = self.build_record(
            timestamp=timestamp,
            severity=severity,
            host=host,
            srcip=srcip,
            dstip=dstip,
            message=payload,
            raw_fields=kv_dict
        )
        if rec and 'severity' in rec:
            rec['severity_int'] = self._severity_to_int(rec['severity'])
        return rec

    def _parse_leef_line(self, line):
        parts = line.split('|', 5)
        if len(parts) < 6:
            return None
        kv_str = parts[5].strip()
        kv_dict = {}
        pairs = re.findall(r'(\w+?)=(.*?)(?=\t|\s+\w+=|$)', kv_str)
        for key, val in pairs:
            kv_dict[key.lower()] = val.strip()
        timestamp = ''
        if 'devtime' in kv_dict:
            ts_val = kv_dict['devtime']
            if ts_val.replace('.', '', 1).isdigit():
                try:
                    ts_float = float(ts_val)
                    timestamp = datetime.fromtimestamp(ts_float).isoformat()
                except Exception:
                    timestamp = ts_val
            else:
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
            else:
                severity = 'INFO'
        srcip = kv_dict.get('src', kv_dict.get('srcip', kv_dict.get('source ip', '')))
        dstip = kv_dict.get('dst', kv_dict.get('dstip', kv_dict.get('destination ip', '')))
        host = kv_dict.get('origin', '')
        message = line
        rec = self.build_record(
            timestamp=timestamp,
            severity=severity,
            host=host,
            srcip=srcip,
            dstip=dstip,
            message=message,
            raw_fields=kv_dict
        )
        if rec and 'severity' in rec:
            rec['severity_int'] = self._severity_to_int(rec['severity'])
        return rec

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
                    "sid":          {"type": "long"},
                    "message":      {"type": "text"},
                    "raw_fields":   {"type": "object", "enabled": True}
                }
            }
        }
