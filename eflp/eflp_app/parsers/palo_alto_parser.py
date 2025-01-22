import re
from parsers.base_parser import BaseParser

class PaloAltoParser(BaseParser):
    SYSLOG_REGEX = re.compile(r'^<(?P<priority>\d+)>\S*\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<payload>.*)$')

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
                sys_ts = m.group('timestamp')
                sys_host = m.group('host')
                payload = m.group('payload')
                fields = payload.split(',')
                if len(fields) < 4:
                    continue
                pan_raw_type = fields[3].strip().upper()
                severity = 'INFO'
                if pan_raw_type == 'THREAT':
                    severity = 'HIGH'
                elif pan_raw_type == 'SYSTEM':
                    severity = 'MEDIUM'
                dt = fields[1].strip() if len(fields) > 1 else sys_ts
                msg_parts = []
                if len(fields) >= 5:
                    msg_parts.append(f"Host: {fields[4]}")
                if len(fields) >= 7:
                    msg_parts.append(f"Extra: {fields[6]}")
                msg = " | ".join(msg_parts) if msg_parts else payload
                rec = {
                    'timestamp': dt,
                    'severity': severity,
                    'message': msg,
                    'syslog_priority': priority,
                    'syslog_timestamp': sys_ts,
                    'syslog_host': sys_host,
                    'raw_pan_type': pan_raw_type
                }
                data.append(rec)
        return data
