from datetime import datetime
from parsers.base_parser import BaseParser


class MerakiParser(BaseParser):
    EVENT_CATEGORY_HINTS = {
        "ids": "threat",
        "ips": "threat",
        "malware": "malware",
        "vpn": "vpn",
        "ipsec": "vpn",
        "client_vpn": "vpn",
        "authentication": "authentication",
        "login": "authentication",
        "security": "threat",
        "traffic": "traffic",
        "flows": "traffic",
        "system": "system",
        "config": "configuration",
        "wireless": "wireless",
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

                raw_fields = self.parse_json_line(payload)
                timestamp = ""
                event_type = ""
                device_id = ""
                leftover = []

                if raw_fields:
                    timestamp = self.first_value(raw_fields.get("timestamp"), raw_fields.get("occurredat"), raw_fields.get("time"))
                    event_type = self.first_value(raw_fields.get("eventtype"), raw_fields.get("event"), raw_fields.get("type"))
                    device_id = self.first_value(raw_fields.get("deviceid"), raw_fields.get("networkid"), raw_fields.get("device"))
                else:
                    tokens = payload.split()
                    raw_fields, leftover, timestamp, device_id, event_type = self._parse_tokens(tokens)

                severity = self.normalize_severity(raw_fields.get("severity"), fallback="INFO")
                severity = self.normalize_severity(self.first_value(raw_fields.get("priority"), severity), fallback=severity)

                action = self.normalize_action(self.first_value(raw_fields.get("action"), raw_fields.get("decision"), raw_fields.get("result")), payload)
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                message = self.first_value(raw_fields.get("message"), raw_fields.get("msg"), " ".join(leftover), payload)
                srcip, srcport = self._parse_ip_port(self.first_value(raw_fields.get("src"), raw_fields.get("srcip"), raw_fields.get("clientip")))
                dstip, dstport = self._parse_ip_port(self.first_value(raw_fields.get("dst"), raw_fields.get("dstip"), raw_fields.get("serverip")))

                category = self._infer_category(event_type, payload)

                record = {
                    "timestamp": self.first_value(timestamp, raw_fields.get("timestamp"), meta.get("timestamp") if meta else ""),
                    "severity": severity,
                    "host": self.first_value(meta.get("host") if meta else "", device_id, raw_fields.get("host")),
                    "message": message,
                    "event": self.first_value(event_type, raw_fields.get("event"), raw_fields.get("eventtype")),
                    "action": action,
                    "log_category": category,
                    "src_ip": srcip,
                    "dst_ip": dstip,
                    "src_port": self.first_value(raw_fields.get("sport"), raw_fields.get("srcport"), srcport),
                    "dst_port": self.first_value(raw_fields.get("dport"), raw_fields.get("dstport"), dstport),
                    "protocol": self.first_value(raw_fields.get("proto"), raw_fields.get("protocol")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("username"), raw_fields.get("clientmac")),
                    "rule": self.first_value(raw_fields.get("rule"), raw_fields.get("policy"), raw_fields.get("ssid")),
                    "event_id": self.first_value(raw_fields.get("eventid"), raw_fields.get("id")),
                    "session_id": self.first_value(raw_fields.get("sessionid"), raw_fields.get("flowid")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="meraki", default_category=category)
                records.append(record)

        return records

    def _parse_tokens(self, tokens):
        event_type = ""
        device_id = ""
        timestamp = ""

        if tokens and self._is_numeric(tokens[0]):
            timestamp = self._parse_timestamp(tokens.pop(0))

        if tokens and "=" not in tokens[0]:
            device_id = tokens.pop(0)
        if tokens and "=" not in tokens[0]:
            event_type = tokens.pop(0)

        raw_fields = {}
        leftover = []
        idx = 0
        while idx < len(tokens):
            token = tokens[idx]
            if "=" in token:
                key, value = token.split("=", 1)
                raw_fields[key.strip().lower()] = self.clean_value(value)
                idx += 1
                continue
            if token.endswith(":") and idx + 1 < len(tokens):
                key = token[:-1].strip().lower()
                j = idx + 1
                value_tokens = []
                while j < len(tokens) and "=" not in tokens[j]:
                    value_tokens.append(tokens[j])
                    j += 1
                raw_fields[key] = " ".join(value_tokens).strip()
                idx = j
                continue
            leftover.append(token)
            idx += 1

        if device_id:
            raw_fields.setdefault("device_id", device_id)
        if event_type:
            raw_fields.setdefault("event_type", event_type)

        return raw_fields, leftover, timestamp, device_id, event_type

    def _is_numeric(self, token):
        try:
            float(token)
            return True
        except ValueError:
            return False

    def _parse_timestamp(self, token):
        try:
            return datetime.fromtimestamp(float(token)).isoformat()
        except Exception:
            return token

    def _parse_ip_port(self, value):
        if not value:
            return "", None
        text = str(value)
        if ":" in text and text.count(":") == 1:
            ip, port = text.split(":", 1)
            return self.normalize_ip(ip), self.normalize_port(port)
        return self.normalize_ip(text), None

    def _infer_category(self, event_type, message):
        haystack = f"{event_type or ''} {message or ''}".lower()
        for needle, category in self.EVENT_CATEGORY_HINTS.items():
            if needle in haystack:
                return category
        return "unknown"

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
