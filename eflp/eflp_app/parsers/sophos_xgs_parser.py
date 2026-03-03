from parsers.base_parser import BaseParser


class SophosXGSParser(BaseParser):
    TYPE_TO_CATEGORY = {
        "firewall": "traffic",
        "ips": "threat",
        "atp": "threat",
        "web": "web",
        "proxy": "web",
        "vpn": "vpn",
        "auth": "authentication",
        "system": "system",
        "dns": "dns",
        "waf": "threat",
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

                if payload.lower().startswith("sophosxgs:"):
                    payload = payload[len("sophosxgs:"):].strip()

                raw_fields = self.parse_kv_pairs(payload)
                raw_fields.update(self.parse_json_line(payload))

                action = self.normalize_action(
                    self.first_value(raw_fields.get("action"), raw_fields.get("result"), raw_fields.get("status")),
                    payload,
                )

                severity = self.normalize_severity(
                    self.first_value(raw_fields.get("severity"), raw_fields.get("priority"), meta.get("priority") if meta else ""),
                    fallback="INFO",
                )
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                log_type = str(self.first_value(raw_fields.get("type"), raw_fields.get("log_type"), raw_fields.get("subtype"), raw_fields.get("module"))).lower()
                category = self.TYPE_TO_CATEGORY.get(log_type, "unknown")

                record = {
                    "timestamp": self.first_value(
                        raw_fields.get("timestamp"),
                        f"{raw_fields.get('date', '')} {raw_fields.get('time', '')}".strip(),
                        meta.get("timestamp") if meta else "",
                    ),
                    "severity": severity,
                    "host": self.first_value(meta.get("host") if meta else "", raw_fields.get("device_name"), raw_fields.get("hostname")),
                    "message": self.first_value(raw_fields.get("msg"), raw_fields.get("message"), payload),
                    "event": self.first_value(raw_fields.get("event"), raw_fields.get("subtype"), raw_fields.get("log_component"), raw_fields.get("id")),
                    "action": action,
                    "log_category": category,
                    "src_ip": self.first_value(raw_fields.get("src_ip"), raw_fields.get("srcip"), raw_fields.get("src")),
                    "dst_ip": self.first_value(raw_fields.get("dst_ip"), raw_fields.get("dstip"), raw_fields.get("dst")),
                    "src_port": self.first_value(raw_fields.get("src_port"), raw_fields.get("srcport"), raw_fields.get("sport")),
                    "dst_port": self.first_value(raw_fields.get("dst_port"), raw_fields.get("dstport"), raw_fields.get("dport")),
                    "protocol": self.first_value(raw_fields.get("protocol"), raw_fields.get("proto")),
                    "rule": self.first_value(raw_fields.get("fw_rule_id"), raw_fields.get("policy_name"), raw_fields.get("rule")),
                    "signature": self.first_value(raw_fields.get("signature"), raw_fields.get("threat_name"), raw_fields.get("alert_name")),
                    "event_id": self.first_value(raw_fields.get("id"), raw_fields.get("eventid"), raw_fields.get("logid")),
                    "session_id": self.first_value(raw_fields.get("session_id"), raw_fields.get("sid"), raw_fields.get("connid")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("username"), raw_fields.get("srcuser"), raw_fields.get("dstuser")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="sophos_xgs", default_category=category)
                records.append(record)

        return records

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
