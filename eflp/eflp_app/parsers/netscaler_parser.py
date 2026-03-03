import re
from parsers.base_parser import BaseParser


class NetscalerParser(BaseParser):
    VENDOR = "netscaler"
    SYSLOG_RE = re.compile(
        r'^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<tag>[\w\-/\[\]\.:]+)\s*:\s*(?P<msg>.*)$'
    )
    ARROW_IP_RE = re.compile(r'(?P<src>(?:\d{1,3}\.){3}\d{1,3})\s*->\s*(?P<dst>(?:\d{1,3}\.){3}\d{1,3})')

    TAG_CATEGORY = {
        "APPFW": "threat",
        "NSVPN": "vpn",
        "SSLVPN": "vpn",
        "AAA": "authentication",
        "AUTH": "authentication",
        "SYSTEM": "system",
        "HA": "ha",
        "CLUSTER": "ha",
        "CONFIG": "configuration",
        "CMD": "configuration",
    }

    def parse(self, file_path):
        records = []
        with open(file_path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                tag = ""
                host = ""
                msg = line
                ts = ""

                tagged = self.SYSLOG_RE.match(line)
                if tagged:
                    ts = tagged.group("ts") or ""
                    host = tagged.group("host") or ""
                    tag = (tagged.group("tag") or "").strip()
                    msg = (tagged.group("msg") or "").strip()

                meta = self.parse_syslog_prefix(line)
                payload = meta.get("payload", msg) if meta else msg

                raw_fields = self.parse_kv_pairs(payload)
                raw_fields.update(self.parse_json_line(payload))

                src_ip, dst_ip = self._extract_arrow_ips(payload)
                action = self.normalize_action(
                    self.first_value(raw_fields.get("action"), raw_fields.get("result"), raw_fields.get("status")),
                    payload,
                )
                severity = self.normalize_severity(
                    self.first_value(raw_fields.get("severity"), raw_fields.get("level"), raw_fields.get("pri"), meta.get("priority") if meta else ""),
                    fallback="INFO",
                )
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                category = self._category_from_tag(tag, payload)

                record = {
                    "timestamp": self.first_value(
                        raw_fields.get("timestamp"),
                        raw_fields.get("time"),
                        ts,
                        meta.get("timestamp") if meta else "",
                    ),
                    "severity": severity,
                    "host": self.first_value(host, meta.get("host") if meta else "", raw_fields.get("hostname")),
                    "message": payload,
                    "event": self.first_value(raw_fields.get("event"), raw_fields.get("eventname"), raw_fields.get("signature"), tag),
                    "action": action,
                    "log_category": category,
                    "src_ip": self.first_value(raw_fields.get("src"), raw_fields.get("srcip"), raw_fields.get("clientip"), src_ip),
                    "dst_ip": self.first_value(raw_fields.get("dst"), raw_fields.get("dstip"), raw_fields.get("serverip"), dst_ip),
                    "src_port": self.first_value(raw_fields.get("sport"), raw_fields.get("srcport")),
                    "dst_port": self.first_value(raw_fields.get("dport"), raw_fields.get("dstport")),
                    "protocol": self.first_value(raw_fields.get("proto"), raw_fields.get("protocol")),
                    "rule": self.first_value(raw_fields.get("policy"), raw_fields.get("policyname"), raw_fields.get("profile")),
                    "signature": self.first_value(raw_fields.get("signature"), raw_fields.get("attack"), raw_fields.get("threat")),
                    "event_id": self.first_value(raw_fields.get("eventid"), raw_fields.get("id"), raw_fields.get("msgid")),
                    "session_id": self.first_value(raw_fields.get("sessionid"), raw_fields.get("sid"), raw_fields.get("connid")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("username"), raw_fields.get("aaauser")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor=self.VENDOR, default_category=category)
                records.append(record)

        return records

    def _extract_arrow_ips(self, payload):
        match = self.ARROW_IP_RE.search(payload)
        if not match:
            return "", ""
        return match.group("src") or "", match.group("dst") or ""

    def _category_from_tag(self, tag, payload):
        haystack = f"{tag or ''} {payload or ''}".upper()
        for hint, category in self.TAG_CATEGORY.items():
            if hint in haystack:
                return category
        return "unknown"

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
