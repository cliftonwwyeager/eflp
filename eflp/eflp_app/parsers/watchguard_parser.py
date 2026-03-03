import re
from parsers.base_parser import BaseParser


class WatchguardParser(BaseParser):
    KEYVAL_REGEX = re.compile(r'(\w+)=((?:"[^"]*")|\S+)')

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
                raw_fields.update(self._parse_keyval(payload))

                positional = self._parse_positional(payload)
                if positional:
                    raw_fields.update({k: v for k, v in positional.items() if k not in raw_fields or not raw_fields[k]})

                message = self.first_value(raw_fields.get("msg"), raw_fields.get("message"), payload)
                action = self.normalize_action(
                    self.first_value(raw_fields.get("action"), raw_fields.get("disp"), raw_fields.get("op"), positional.get("action") if positional else ""),
                    message,
                )

                severity = self.normalize_severity(
                    self.first_value(raw_fields.get("severity"), meta.get("priority") if meta else ""),
                    fallback="INFO",
                )
                if severity == "INFO" and action in {"deny", "reset", "quarantine"}:
                    severity = "HIGH"

                category = "unknown"
                msg_id = str(self.first_value(raw_fields.get("msg_id"), raw_fields.get("id"))).lower()
                if "proxy" in payload.lower() or "http" in payload.lower():
                    category = "web"
                elif any(k in payload.lower() for k in ["auth", "login", "logout", "radius"]):
                    category = "authentication"
                elif any(k in payload.lower() for k in ["vpn", "ike", "ipsec", "mobile vpn"]):
                    category = "vpn"
                elif any(k in payload.lower() for k in ["ips", "attack", "botnet", "threat"]):
                    category = "threat"
                elif msg_id.startswith("3000") or "firewall" in payload.lower():
                    category = "traffic"
                elif any(k in payload.lower() for k in ["config", "policy", "admin"]):
                    category = "configuration"
                elif any(k in payload.lower() for k in ["system", "cpu", "memory", "cluster"]):
                    category = "system"

                record = {
                    "timestamp": self.first_value(raw_fields.get("timestamp"), meta.get("timestamp") if meta else "", positional.get("timestamp") if positional else ""),
                    "severity": severity,
                    "host": self.first_value(meta.get("host") if meta else "", raw_fields.get("member"), positional.get("host") if positional else ""),
                    "message": message,
                    "event": self.first_value(raw_fields.get("event"), raw_fields.get("msg_id"), raw_fields.get("subj")),
                    "action": action,
                    "log_category": category,
                    "src_ip": self.first_value(raw_fields.get("src"), raw_fields.get("src_ip"), positional.get("src_ip") if positional else ""),
                    "dst_ip": self.first_value(raw_fields.get("dst"), raw_fields.get("dst_ip"), positional.get("dst_ip") if positional else ""),
                    "src_port": self.first_value(raw_fields.get("srcport"), raw_fields.get("sport"), positional.get("src_port") if positional else ""),
                    "dst_port": self.first_value(raw_fields.get("dstport"), raw_fields.get("dport"), positional.get("dst_port") if positional else ""),
                    "protocol": self.first_value(raw_fields.get("proto"), raw_fields.get("protocol"), positional.get("protocol") if positional else ""),
                    "rule": self.first_value(raw_fields.get("policy"), raw_fields.get("rule"), raw_fields.get("firewall_policy")),
                    "signature": self.first_value(raw_fields.get("sig"), raw_fields.get("signature"), raw_fields.get("threat")),
                    "event_id": self.first_value(raw_fields.get("msg_id"), raw_fields.get("id")),
                    "session_id": self.first_value(raw_fields.get("sessionid"), raw_fields.get("connid"), raw_fields.get("sid")),
                    "user": self.first_value(raw_fields.get("user"), raw_fields.get("srcuser"), raw_fields.get("dstuser")),
                    "raw_fields": raw_fields,
                    "syslog_priority": meta.get("priority") if meta else None,
                }

                record = self.enrich_record(record, vendor="watchguard", default_category=category)
                records.append(record)

        return records

    def _parse_keyval(self, payload):
        parsed = {}
        for key, value in self.KEYVAL_REGEX.findall(payload):
            parsed[key.lower()] = self.clean_value(value)
        return parsed

    def _parse_positional(self, payload):
        tokens = payload.split()
        if len(tokens) < 9:
            return {}

        timestamp = f"{tokens[0]} {tokens[1]}"
        return {
            "timestamp": timestamp,
            "host": tokens[2],
            "action": tokens[3],
            "src_ip": tokens[4],
            "dst_ip": tokens[5],
            "protocol": tokens[6],
            "src_port": tokens[7],
            "dst_port": tokens[8],
        }

    def get_elasticsearch_mapping(self):
        return self.get_base_elasticsearch_mapping()
