import re
from datetime import datetime
from parsers.base_parser import BaseParser


class CheckpointParser(BaseParser):
    LEEF_REGEX = re.compile(r'^LEEF:\d+\|Check Point\|', re.IGNORECASE)

    def parse(self, file_path):
        records = []
        with open(file_path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                if self.LEEF_REGEX.match(line):
                    record = self._parse_leef_line(line)
                    if record:
                        records.append(record)
                    continue

                meta = self.parse_syslog_prefix(line)
                payload = meta.get("payload", "") if meta else line

                raw_fields = self.parse_kv_pairs(payload)
                if not raw_fields:
                    raw_fields = self._parse_semicolon_pairs(payload)

                severity = self.normalize_severity(
                    self.first_value(raw_fields.get("severity"), raw_fields.get("syslog_severity"), meta.get("priority") if meta else ""),
                    fallback="INFO",
                )
                action = self.normalize_action(self.first_value(raw_fields.get("action"), raw_fields.get("result"), raw_fields.get("product")), payload)
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                record = {
                    "timestamp": self.first_value(
                        raw_fields.get("time"),
                        raw_fields.get("timestamp"),
                        meta.get("timestamp") if meta else "",
                    ),
                    "severity": severity,
                    "host": self.first_value(meta.get("host") if meta else "", raw_fields.get("origin"), raw_fields.get("device_name")),
                    "message": self.first_value(raw_fields.get("msg"), payload),
                    "event": self.first_value(raw_fields.get("event_type"), raw_fields.get("product"), raw_fields.get("attack"), raw_fields.get("action")),
                    "action": action,
                    "log_category": "unknown",
                    "src_ip": self.first_value(raw_fields.get("src"), raw_fields.get("source"), raw_fields.get("srcip")),
                    "dst_ip": self.first_value(raw_fields.get("dst"), raw_fields.get("destination"), raw_fields.get("dstip")),
                    "src_port": self.first_value(raw_fields.get("s_port"), raw_fields.get("srcport")),
                    "dst_port": self.first_value(raw_fields.get("service"), raw_fields.get("dstport")),
                    "protocol": self.first_value(raw_fields.get("proto"), raw_fields.get("service_id")),
                    "rule": self.first_value(raw_fields.get("rule_name"), raw_fields.get("policy_name"), raw_fields.get("layer_name")),
                    "signature": self.first_value(raw_fields.get("attack"), raw_fields.get("protection_name")),
                    "event_id": self.first_value(raw_fields.get("logid"), raw_fields.get("id"), raw_fields.get("protection_id")),
                    "session_id": self.first_value(raw_fields.get("session_id"), raw_fields.get("sid")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("src_user_name"), raw_fields.get("dst_user_name")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="checkpoint", default_category="unknown")
                records.append(record)

        return records

    def _parse_semicolon_pairs(self, payload):
        parsed = {}
        for chunk in payload.split(";"):
            if "=" in chunk:
                key, value = chunk.split("=", 1)
            elif ":" in chunk:
                key, value = chunk.split(":", 1)
            else:
                continue
            key = key.strip().lower()
            value = self.clean_value(value)
            if key:
                parsed[key] = value
        return parsed

    def _parse_leef_line(self, line):
        parts = line.split("|", 5)
        if len(parts) < 6:
            return None

        payload = parts[5]
        raw_fields = {}
        for key, val in re.findall(r'(\w+?)=(.*?)(?=\t|\s+\w+=|$)', payload):
            raw_fields[key.lower()] = self.clean_value(val)

        devtime = raw_fields.get("devtime")
        timestamp = ""
        if devtime:
            ts_float = self.to_float(devtime)
            if ts_float is not None:
                timestamp = datetime.fromtimestamp(ts_float).isoformat()
            else:
                timestamp = devtime

        severity = self.normalize_severity(
            self.first_value(raw_fields.get("severity"), raw_fields.get("syslog_severity")),
            fallback="INFO",
        )

        record = {
            "timestamp": timestamp,
            "severity": severity,
            "host": self.first_value(raw_fields.get("origin"), raw_fields.get("dvc"), raw_fields.get("dhost")),
            "message": line,
            "event": self.first_value(raw_fields.get("cat"), raw_fields.get("eventid"), raw_fields.get("action")),
            "action": self.normalize_action(raw_fields.get("action"), line),
            "log_category": "unknown",
            "src_ip": self.first_value(raw_fields.get("src"), raw_fields.get("srcip")),
            "dst_ip": self.first_value(raw_fields.get("dst"), raw_fields.get("dstip")),
            "src_port": self.first_value(raw_fields.get("srcport"), raw_fields.get("spt")),
            "dst_port": self.first_value(raw_fields.get("dstport"), raw_fields.get("dpt")),
            "protocol": raw_fields.get("proto"),
            "rule": self.first_value(raw_fields.get("rule_name"), raw_fields.get("policy_name")),
            "signature": self.first_value(raw_fields.get("attack"), raw_fields.get("protection_name")),
            "event_id": self.first_value(raw_fields.get("eventid"), raw_fields.get("id")),
            "session_id": self.first_value(raw_fields.get("session_id"), raw_fields.get("sid")),
            "user": self.first_value(raw_fields.get("user"), raw_fields.get("usrname"), raw_fields.get("src_user_name")),
            "raw_fields": raw_fields,
        }

        return self.enrich_record(record, vendor="checkpoint", default_category="unknown")

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
