from parsers.base_parser import BaseParser


class SophosUTMParser(BaseParser):
    TYPE_TO_CATEGORY = {
        "firewall": "traffic",
        "utm": "threat",
        "web": "web",
        "proxy": "web",
        "vpn": "vpn",
        "auth": "authentication",
        "system": "system",
        "dns": "dns",
        "smtp": "threat",
        "ips": "threat",
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

                if payload.lower().startswith("sophosutm:"):
                    payload = payload[len("sophosutm:"):].strip()

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

                log_type = str(self.first_value(raw_fields.get("type"), raw_fields.get("subtype"), raw_fields.get("service"))).lower()
                category = self.TYPE_TO_CATEGORY.get(log_type, "unknown")

                record = {
                    "timestamp": self.first_value(
                        raw_fields.get("timestamp"),
                        f"{raw_fields.get('date', '')} {raw_fields.get('time', '')}".strip(),
                        meta.get("timestamp") if meta else "",
                    ),
                    "severity": severity,
                    "host": self.first_value(meta.get("host") if meta else "", raw_fields.get("device"), raw_fields.get("hostname")),
                    "message": self.first_value(raw_fields.get("msg"), raw_fields.get("message"), payload),
                    "event": self.first_value(raw_fields.get("event"), raw_fields.get("subtype"), raw_fields.get("log_type"), raw_fields.get("id")),
                    "action": action,
                    "log_category": category,
                    "src_ip": self.first_value(raw_fields.get("src"), raw_fields.get("srcip")),
                    "dst_ip": self.first_value(raw_fields.get("dst"), raw_fields.get("dstip")),
                    "src_port": self.first_value(raw_fields.get("sport"), raw_fields.get("srcport")),
                    "dst_port": self.first_value(raw_fields.get("dport"), raw_fields.get("dstport")),
                    "protocol": self.first_value(raw_fields.get("proto"), raw_fields.get("protocol")),
                    "rule": self.first_value(raw_fields.get("rule"), raw_fields.get("policy"), raw_fields.get("fw_rule_id")),
                    "signature": self.first_value(raw_fields.get("signature"), raw_fields.get("threatname"), raw_fields.get("virusname")),
                    "event_id": self.first_value(raw_fields.get("id"), raw_fields.get("eventid"), raw_fields.get("logid")),
                    "session_id": self.first_value(raw_fields.get("sessionid"), raw_fields.get("sid"), raw_fields.get("connid")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("srcuser"), raw_fields.get("dstuser"), raw_fields.get("srcname")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="sophos_utm", default_category=category)
                records.append(record)

        return records

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
