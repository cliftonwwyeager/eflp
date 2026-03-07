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
