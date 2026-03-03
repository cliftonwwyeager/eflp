from parsers.base_parser import BaseParser


class SonicwallParser(BaseParser):
    TYPE_TO_CATEGORY = {
        "firewall": "traffic",
        "utm": "threat",
        "gateway antivir": "malware",
        "gateway anti-virus": "malware",
        "ips": "threat",
        "ids": "threat",
        "vpn": "vpn",
        "system": "system",
        "auth": "authentication",
        "app control": "threat",
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

                severity = self.normalize_severity(raw_fields.get("severity"), fallback="INFO")
                if severity == "INFO":
                    severity = self.normalize_severity(raw_fields.get("pri"), fallback="INFO")

                message = self.first_value(raw_fields.get("msg"), raw_fields.get("m"), payload)
                action = self.normalize_action(
                    self.first_value(raw_fields.get("act"), raw_fields.get("action"), raw_fields.get("result")),
                    message,
                )
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                msg_type = str(self.first_value(raw_fields.get("c"), raw_fields.get("cat"), raw_fields.get("type"))).lower()
                category = self.TYPE_TO_CATEGORY.get(msg_type, "unknown")

                record = {
                    "timestamp": self.first_value(
                        raw_fields.get("time"),
                        raw_fields.get("timestamp"),
                        meta.get("timestamp") if meta else "",
                    ),
                    "severity": severity,
                    "host": self.first_value(
                        meta.get("host") if meta else "",
                        raw_fields.get("sn"),
                        raw_fields.get("devname"),
                    ),
                    "message": message,
                    "event": self.first_value(raw_fields.get("id"), raw_fields.get("msgid"), raw_fields.get("evt")),
                    "action": action,
                    "log_category": category,
                    "src_ip": self.first_value(raw_fields.get("src"), raw_fields.get("srcip")),
                    "dst_ip": self.first_value(raw_fields.get("dst"), raw_fields.get("dstip")),
                    "src_port": self.first_value(raw_fields.get("sport"), raw_fields.get("srcport")),
                    "dst_port": self.first_value(raw_fields.get("dport"), raw_fields.get("dstport")),
                    "session_id": self.first_value(raw_fields.get("sessionid"), raw_fields.get("sid")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("usr"), raw_fields.get("dstuser")),
                    "protocol": self.first_value(raw_fields.get("proto"), raw_fields.get("protocol")),
                    "rule": self.first_value(raw_fields.get("policy"), raw_fields.get("fw_rule"), raw_fields.get("rule")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="sonicwall", default_category=category)
                records.append(record)
        return records

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
