import csv
import re
from parsers.base_parser import BaseParser


class PaloAltoParser(BaseParser):
    TYPE_TO_CATEGORY = {
        "TRAFFIC": "traffic",
        "THREAT": "threat",
        "URL": "web",
        "WILDFIRE": "malware",
        "SYSTEM": "system",
        "CONFIG": "configuration",
        "HIPMATCH": "authentication",
        "USERID": "authentication",
        "GLOBALPROTECT": "vpn",
        "TUNNEL": "vpn",
        "AUTHENTICATION": "authentication",
        "DECRYPTION": "threat",
        "CORRELATION": "threat",
    }

    ACTION_HINTS = {
        "allow", "accept", "permit", "drop", "deny", "reset-both",
        "reset-client", "reset-server", "block", "alert", "override",
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
                csv_fields = self._parse_csv_fields(payload)

                log_type, subtype = self._extract_type_subtype(csv_fields, raw_fields)
                action = self._extract_action(csv_fields, raw_fields, payload)
                src_ip, dst_ip, src_port, dst_port = self._extract_network_tuple(csv_fields, raw_fields)

                message = self.first_value(
                    raw_fields.get("msg"),
                    raw_fields.get("message"),
                    payload,
                )
                severity = self.normalize_severity(raw_fields.get("severity"), fallback="INFO")
                if severity == "INFO" and (action in {"deny", "reset", "quarantine"} or log_type in {"THREAT", "WILDFIRE", "CORRELATION"}):
                    severity = "HIGH"

                if log_type:
                    raw_fields.setdefault("type", log_type)
                if subtype:
                    raw_fields.setdefault("subtype", subtype)

                record = {
                    "timestamp": self.first_value(
                        raw_fields.get("generated_time"),
                        raw_fields.get("receive_time"),
                        csv_fields[6] if len(csv_fields) > 6 else "",
                        csv_fields[0] if csv_fields else "",
                        meta.get("timestamp") if meta else "",
                    ),
                    "severity": severity,
                    "host": self.first_value(meta.get("host") if meta else "", raw_fields.get("serial"), raw_fields.get("device_name")),
                    "message": message,
                    "action": action,
                    "event": self.first_value(raw_fields.get("eventid"), raw_fields.get("event"), subtype, log_type),
                    "log_category": self.TYPE_TO_CATEGORY.get(log_type, "unknown"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "syslog_priority": meta.get("priority") if meta else None,
                    "raw_fields": raw_fields,
                }

                record = self.enrich_record(record, vendor="palo_alto", default_category=self.TYPE_TO_CATEGORY.get(log_type, "unknown"))
                records.append(record)
        return records

    def _parse_csv_fields(self, payload):
        if "," not in payload:
            return []
        try:
            values = next(csv.reader([payload]))
            return [self.clean_value(v) for v in values]
        except Exception:
            return []

    def _extract_type_subtype(self, fields, raw_fields):
        log_type = str(raw_fields.get("type", raw_fields.get("log_type", ""))).upper()
        subtype = str(raw_fields.get("subtype", raw_fields.get("event_type", "")))
        if log_type:
            return log_type, subtype

        for idx, value in enumerate(fields):
            candidate = str(value).upper()
            if candidate in self.TYPE_TO_CATEGORY:
                next_field = fields[idx + 1] if idx + 1 < len(fields) else ""
                return candidate, str(next_field)
        return "", subtype

    def _extract_action(self, fields, raw_fields, payload):
        action = self.normalize_action(raw_fields.get("action"), payload)
        if action:
            return action

        for value in fields:
            candidate = str(value).strip().lower()
            if candidate in self.ACTION_HINTS:
                return self.normalize_action(candidate, payload)

        if re.search(r"\b(reset|deny|drop|block)\b", payload, re.IGNORECASE):
            return "deny"
        if re.search(r"\b(allow|accept|permit)\b", payload, re.IGNORECASE):
            return "allow"
        return ""

    def _extract_network_tuple(self, fields, raw_fields):
        src_ip = self.normalize_ip(raw_fields.get("src"))
        dst_ip = self.normalize_ip(raw_fields.get("dst"))
        src_port = self.normalize_port(raw_fields.get("sport"))
        dst_port = self.normalize_port(raw_fields.get("dport"))

        if not src_ip or not dst_ip:
            ips = [self.normalize_ip(value) for value in fields]
            ips = [ip for ip in ips if ip]
            if not src_ip and ips:
                src_ip = ips[0]
            if not dst_ip and len(ips) > 1:
                dst_ip = ips[1]

        if src_port is None or dst_port is None:
            ports = [self.normalize_port(value) for value in fields]
            ports = [p for p in ports if p is not None]
            if src_port is None and ports:
                src_port = ports[0]
            if dst_port is None and len(ports) > 1:
                dst_port = ports[1]

        return src_ip, dst_ip, src_port, dst_port

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
