from parsers.base_parser import BaseParser


class FortigateParser(BaseParser):
    LEVEL_TO_SEVERITY = {
        "emergency": "CRITICAL",
        "alert": "CRITICAL",
        "critical": "CRITICAL",
        "error": "HIGH",
        "warning": "MEDIUM",
        "notice": "LOW",
        "information": "INFO",
        "debug": "INFO",
    }

    TYPE_TO_CATEGORY = {
        "traffic": "traffic",
        "utm": "threat",
        "event": "system",
        "anomaly": "threat",
        "vpn": "vpn",
        "system": "system",
        "wireless": "wireless",
        "dns": "dns",
        "attack": "threat",
        "admin": "configuration",
    }

    def parse(self, file_path):
        records = []
        with open(file_path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                meta = self.parse_syslog_prefix(line)
                payload = meta.get("payload", "") if meta else line
                raw_fields = self.parse_kv_pairs(payload)
                if not raw_fields:
                    raw_fields = self.parse_kv_pairs(line)

                fgt_type = str(self.first_value(raw_fields.get("type"), raw_fields.get("log_type"))).lower()
                subtype = str(self.first_value(raw_fields.get("subtype"), raw_fields.get("eventtype"))).lower()
                category = self.TYPE_TO_CATEGORY.get(fgt_type, "unknown")
                if subtype in {"vpn", "ipsec", "ssl"}:
                    category = "vpn"
                elif subtype in {"system", "event", "health"}:
                    category = "system"

                level = str(raw_fields.get("level", "")).lower()
                severity = self.normalize_severity(self.LEVEL_TO_SEVERITY.get(level, raw_fields.get("severity")), fallback="INFO")
                action = self.normalize_action(raw_fields.get("action"), payload)
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                sentbyte = self.to_int(raw_fields.get("sentbyte"))
                rcvdbyte = self.to_int(raw_fields.get("rcvdbyte"))
                sentpkt = self.to_int(raw_fields.get("sentpkt"))
                rcvdpkt = self.to_int(raw_fields.get("rcvdpkt"))

                record = {
                    "timestamp": self.first_value(
                        raw_fields.get("eventtime"),
                        f"{raw_fields.get('date', '')} {raw_fields.get('time', '')}".strip(),
                        meta.get("timestamp") if meta else "",
                    ),
                    "severity": severity,
                    "host": self.first_value(
                        meta.get("host") if meta else "",
                        raw_fields.get("devname"),
                        raw_fields.get("devid"),
                    ),
                    "message": self.first_value(raw_fields.get("msg"), payload),
                    "event": self.first_value(raw_fields.get("eventtype"), raw_fields.get("subtype"), raw_fields.get("logid")),
                    "action": action,
                    "log_category": category,
                    "src_ip": raw_fields.get("srcip"),
                    "dst_ip": raw_fields.get("dstip"),
                    "src_port": self.to_int(raw_fields.get("srcport")),
                    "dst_port": self.to_int(raw_fields.get("dstport")),
                    "session_id": raw_fields.get("sessionid"),
                    "bytes_out": sentbyte,
                    "bytes_in": rcvdbyte,
                    "packets_out": sentpkt,
                    "packets_in": rcvdpkt,
                    "protocol": raw_fields.get("proto"),
                    "rule": self.first_value(raw_fields.get("policyid"), raw_fields.get("policytype"), raw_fields.get("policyname")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("unauthuser"), raw_fields.get("srcname")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="fortigate", default_category=category)
                records.append(record)
        return records

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
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
        records = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = self.SYSLOG_REGEX.match(line)
                if not match:
                    continue
                payload = match.group('payload')
                kv_dict = self._parse_key_values(payload)
                level_str = kv_dict.get('level', '').lower()
                severity = self.LEVEL_TO_SEVERITY.get(level_str, 'INFO')
                timestamp = f"{kv_dict.get('date', '').strip()} {kv_dict.get('time', '').strip()}".strip()
                for field in ['srcport', 'dstport', 'sessionid', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt']:
                    if field in kv_dict:
                        kv_dict[field] = self.to_int(kv_dict[field])
                srcip = kv_dict.get('srcip', '')
                dstip = kv_dict.get('dstip', '')
                record = self.build_record(
                    timestamp=timestamp,
                    severity=severity,
                    srcip=srcip,
                    dstip=dstip,
                    srcport=kv_dict.get('srcport'),
                    dstport=kv_dict.get('dstport'),
                    sessionid=kv_dict.get('sessionid'),
                    sentbyte=kv_dict.get('sentbyte'),
                    rcvdbyte=kv_dict.get('rcvdbyte'),
                    sentpkt=kv_dict.get('sentpkt'),
                    rcvdpkt=kv_dict.get('rcvdpkt'),
                    raw_fields=kv_dict,
                    message=kv_dict.get('msg', '')
                )
                record['severity_int'] = self._severity_to_int(severity)
                records.append(record)
        return records

    def _parse_key_values(self, payload):
        kv_pairs = self.KV_REGEX.findall(payload)
        return {k.lower(): v.strip() for k, v in kv_pairs}

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
                    "sentbyte":     {"type": "long"},
                    "rcvdbyte":     {"type": "long"},
                    "sentpkt":      {"type": "long"},
                    "rcvdpkt":      {"type": "long"},
                    "raw_fields":   {"type": "object", "enabled": True},
                    "message":      {"type": "text"}
                }
            }
        }
