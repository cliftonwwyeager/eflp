import re
from parsers.base_parser import BaseParser


class CiscoFTDParser(BaseParser):
    KEYVAL_REGEX = re.compile(r'(?P<key>[A-Za-z0-9_.\-]+)\s*[:=]\s*(?P<value>"[^"]*"|[^,;]+)')
    ASA_ADDR_REGEX = re.compile(
        r'\bsrc\s+\S*:(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})(?:/(?P<src_port>\d+))?\s+'
        r'dst\s+\S*:(?P<dst_ip>(?:\d{1,3}\.){3}\d{1,3})(?:/(?P<dst_port>\d+))?',
        re.IGNORECASE,
    )
    MSG_ID_REGEX = re.compile(r'%[A-Z\-]+-(?P<sev>\d)-(?P<msg_id>\d+)')

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
                raw_fields.update(self._parse_name_values(payload))

                msg_match = self.MSG_ID_REGEX.search(payload)
                message_id = msg_match.group("msg_id") if msg_match else ""
                severity_hint = msg_match.group("sev") if msg_match else ""

                src_ip, src_port, dst_ip, dst_port = self._extract_asa_network_tuple(payload)

                action = self.normalize_action(
                    self.first_value(raw_fields.get("action"), raw_fields.get("result"), raw_fields.get("verdict")),
                    payload,
                )

                severity = self.normalize_severity(
                    self.first_value(raw_fields.get("severity"), raw_fields.get("priority"), severity_hint),
                    fallback="INFO",
                )
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                event = self.first_value(raw_fields.get("eventtype"), raw_fields.get("signature"), raw_fields.get("sid"), message_id)

                record = {
                    "timestamp": self.first_value(
                        raw_fields.get("timestamp"),
                        f"{meta.get('month', '')} {meta.get('day', '')} {meta.get('time', '')}".strip() if meta else "",
                        meta.get("timestamp") if meta else "",
                    ),
                    "severity": severity,
                    "host": self.first_value(meta.get("host") if meta else "", raw_fields.get("device"), raw_fields.get("sensor")),
                    "message": payload,
                    "event": event,
                    "event_id": message_id,
                    "action": action,
                    "log_category": "unknown",
                    "src_ip": self.first_value(raw_fields.get("srcip"), raw_fields.get("src"), src_ip),
                    "dst_ip": self.first_value(raw_fields.get("dstip"), raw_fields.get("dst"), dst_ip),
                    "src_port": self.first_value(raw_fields.get("srcport"), src_port),
                    "dst_port": self.first_value(raw_fields.get("dstport"), dst_port),
                    "protocol": self.first_value(raw_fields.get("protocol"), raw_fields.get("proto")),
                    "signature": self.first_value(raw_fields.get("signature"), raw_fields.get("msg")),
                    "rule": self.first_value(raw_fields.get("accesscontrolrule"), raw_fields.get("policy"), raw_fields.get("policyname")),
                    "session_id": self.first_value(raw_fields.get("connectionid"), raw_fields.get("flowid"), raw_fields.get("sid")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("username"), raw_fields.get("srcuser")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="cisco_ftd", default_category="unknown")
                records.append(record)

        return records

    def _parse_name_values(self, payload):
        parsed = {}
        for match in self.KEYVAL_REGEX.finditer(payload):
            key = match.group("key").lower().strip()
            val = self.clean_value(match.group("value"))
            if key not in parsed:
                parsed[key] = val
        return parsed

    def _extract_asa_network_tuple(self, payload):
        match = self.ASA_ADDR_REGEX.search(payload)
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
