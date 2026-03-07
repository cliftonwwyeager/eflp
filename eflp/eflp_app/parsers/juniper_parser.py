import re
from parsers.base_parser import BaseParser


class JuniperParser(BaseParser):
    ENDPOINT_REGEX = re.compile(
        r'(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})/(?P<src_port>\d+)\s*->\s*(?P<dst_ip>(?:\d{1,3}\.){3}\d{1,3})/(?P<dst_port>\d+)'
    )

    TAG_CATEGORY = {
        "RT_FLOW": "traffic",
        "RT_IDS": "threat",
        "IDP": "threat",
        "RT_UTM": "malware",
        "KMD": "vpn",
        "IKE": "vpn",
        "IPSEC": "vpn",
        "UI_AUTH_EVENT": "authentication",
        "AUTHD": "authentication",
        "SYSTEM": "system",
        "CHASSIS": "system",
        "CONF": "configuration",
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

                event_tag = self._extract_event_tag(payload)
                category = self._category_from_event_tag(event_tag, payload)

                action = self.normalize_action(
                    self.first_value(raw_fields.get("action"), raw_fields.get("result"), event_tag),
                    payload,
                )

                if "SESSION_CREATE" in payload:
                    action = "allow"
                elif "SESSION_CLOSE" in payload:
                    action = "close"

                severity = self.normalize_severity(
                    self.first_value(raw_fields.get("severity"), raw_fields.get("level"), meta.get("priority") if meta else ""),
                    fallback="INFO",
                )
                if severity == "INFO" and category in {"threat", "malware"}:
                    severity = "HIGH"
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                src_ip, src_port, dst_ip, dst_port = self._extract_endpoints(payload)

                record = {
                    "timestamp": self.first_value(meta.get("timestamp") if meta else "", raw_fields.get("timestamp")),
                    "severity": severity,
                    "host": self.first_value(meta.get("host") if meta else "", raw_fields.get("host"), raw_fields.get("hostname")),
                    "message": payload,
                    "event": self.first_value(raw_fields.get("event"), raw_fields.get("event_type"), event_tag),
                    "action": action,
                    "log_category": category,
                    "src_ip": self.first_value(raw_fields.get("src"), raw_fields.get("srcip"), src_ip),
                    "dst_ip": self.first_value(raw_fields.get("dst"), raw_fields.get("dstip"), dst_ip),
                    "src_port": self.first_value(raw_fields.get("srcport"), raw_fields.get("sport"), src_port),
                    "dst_port": self.first_value(raw_fields.get("dstport"), raw_fields.get("dport"), dst_port),
                    "protocol": self.first_value(raw_fields.get("proto"), raw_fields.get("protocol")),
                    "rule": self.first_value(raw_fields.get("policy"), raw_fields.get("rule"), raw_fields.get("service")),
                    "signature": self.first_value(raw_fields.get("attack"), raw_fields.get("signature"), raw_fields.get("threat_name")),
                    "event_id": self.first_value(raw_fields.get("id"), raw_fields.get("eventid"), raw_fields.get("msgid")),
                    "session_id": self.first_value(raw_fields.get("sessionid"), raw_fields.get("sid"), raw_fields.get("session_id")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("username"), raw_fields.get("srcuser")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="juniper", default_category=category)
                records.append(record)

        return records

    def _extract_event_tag(self, payload):
        tag_match = re.match(r'(?P<tag>[A-Z_]+(?:\[[^\]]+\])?):', payload)
        if tag_match:
            return tag_match.group("tag")
        tokens = payload.split()
        if tokens:
            return tokens[0]
        return ""

    def _category_from_event_tag(self, event_tag, payload):
        haystack = f"{event_tag or ''} {payload or ''}".upper()
        for hint, category in self.TAG_CATEGORY.items():
            if hint in haystack:
                return category
        return "unknown"

    def _extract_endpoints(self, payload):
        match = self.ENDPOINT_REGEX.search(payload)
        if not match:
            return "", None, "", None
        return (
            match.group("src_ip") or "",
            self.normalize_port(match.group("src_port")),
            match.group("dst_ip") or "",
            self.normalize_port(match.group("dst_port")),
        )

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
