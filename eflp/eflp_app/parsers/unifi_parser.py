import re
from parsers.base_parser import BaseParser


class UnifiParser(BaseParser):
    BRACKET_PREFIX = re.compile(r'^\[[^\]]+\]\s*')

    def parse(self, file_path):
        records = []
        with open(file_path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                meta = self.parse_syslog_prefix(line)
                payload = meta.get("payload", "") if meta else line
                payload = self._strip_prefix(payload)

                raw_fields = self.parse_kv_pairs(payload)
                action = self.normalize_action(
                    self.first_value(raw_fields.get("action"), raw_fields.get("result"), raw_fields.get("decision")),
                    payload,
                )

                severity = self.normalize_severity(
                    self.first_value(raw_fields.get("severity"), raw_fields.get("priority"), meta.get("priority") if meta else ""),
                    fallback="INFO",
                )
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                event = self.first_value(
                    raw_fields.get("event"),
                    raw_fields.get("event_type"),
                    raw_fields.get("subsystem"),
                    raw_fields.get("rule"),
                )

                category = "unknown"
                if "ids" in payload.lower() or "ips" in payload.lower():
                    category = "threat"
                elif "wireguard" in payload.lower() or "openvpn" in payload.lower() or "ipsec" in payload.lower():
                    category = "vpn"
                elif "radius" in payload.lower() or "login" in payload.lower() or "auth" in payload.lower():
                    category = "authentication"
                elif "firewall" in payload.lower() or "flow" in payload.lower():
                    category = "traffic"
                elif "system" in payload.lower() or "ubios" in payload.lower():
                    category = "system"

                record = {
                    "timestamp": self.first_value(raw_fields.get("timestamp"), meta.get("timestamp") if meta else ""),
                    "severity": severity,
                    "host": self.first_value(meta.get("host") if meta else "", raw_fields.get("hostname"), raw_fields.get("device")),
                    "message": payload,
                    "event": event,
                    "action": action,
                    "log_category": category,
                    "src_ip": self.first_value(raw_fields.get("src"), raw_fields.get("srcip"), raw_fields.get("source")),
                    "dst_ip": self.first_value(raw_fields.get("dst"), raw_fields.get("dstip"), raw_fields.get("destination")),
                    "src_port": self.first_value(raw_fields.get("spt"), raw_fields.get("srcport"), raw_fields.get("sport")),
                    "dst_port": self.first_value(raw_fields.get("dpt"), raw_fields.get("dstport"), raw_fields.get("dport")),
                    "protocol": self.first_value(raw_fields.get("proto"), raw_fields.get("protocol")),
                    "rule": self.first_value(raw_fields.get("rule"), raw_fields.get("policy")),
                    "signature": self.first_value(raw_fields.get("signature"), raw_fields.get("threat")),
                    "event_id": self.first_value(raw_fields.get("eventid"), raw_fields.get("msgid")),
                    "session_id": self.first_value(raw_fields.get("sessionid"), raw_fields.get("flowid")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("username"), raw_fields.get("mac")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="unifi", default_category=category)
                records.append(record)

        return records

    def _strip_prefix(self, payload):
        text = payload.strip()
        text = self.BRACKET_PREFIX.sub("", text)
        if text.lower().startswith("firewall:"):
            text = text[len("firewall:"):].strip()
        if text.lower().startswith("kernel:"):
            text = text[len("kernel:"):].strip()
        return text

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
