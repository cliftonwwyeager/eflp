from abc import ABC, abstractmethod
from dateutil import parser as date_parser
from datetime import datetime, timedelta
import ipaddress
import json
import logging
import re

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class BaseParser(ABC):
    KV_REGEX = re.compile(
        r'(?P<key>[A-Za-z0-9_.\-]+)\s*(?:=|:)\s*(?P<value>"[^"]*"|\'[^\']*\'|\[[^\]]*\]|[^\s,;]+)'
    )
    SYSLOG_REGEXES = [
        re.compile(
            r'^<(?P<priority>\d+)>\d?\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<payload>.*)$'
        ),
        re.compile(
            r'^<(?P<priority>\d+)>(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<payload>.*)$'
        ),
        re.compile(
            r'^(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<payload>.*)$'
        ),
    ]
    IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DATE_WITH_YEAR_REGEX = re.compile(r'\b\d{1,4}[/-]\d{1,2}[/-]\d{1,4}\b')

    SEVERITY_ALIASES = {
        "EMERG": "CRITICAL",
        "EMERGENCY": "CRITICAL",
        "ALERT": "CRITICAL",
        "CRIT": "CRITICAL",
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "ERR": "HIGH",
        "HIGH": "HIGH",
        "WARN": "MEDIUM",
        "WARNING": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "NOTICE": "LOW",
        "LOW": "LOW",
        "INFO": "INFO",
        "INFORMATION": "INFO",
        "DEBUG": "INFO",
    }

    ACTION_ALIASES = {
        "allow": "allow",
        "accept": "allow",
        "permit": "allow",
        "pass": "allow",
        "deny": "deny",
        "drop": "deny",
        "blocked": "deny",
        "block": "deny",
        "reset": "reset",
        "reject": "deny",
        "teardown": "close",
        "close": "close",
        "timeout": "timeout",
        "login": "login",
        "logon": "login",
        "logout": "logout",
        "auth_success": "auth_success",
        "auth_ok": "auth_success",
        "auth_fail": "auth_fail",
        "auth_failed": "auth_fail",
        "failed": "fail",
        "success": "success",
        "update": "update",
        "create": "create",
        "delete": "delete",
        "modify": "modify",
        "commit": "commit",
        "install": "install",
        "quarantine": "quarantine",
    }

    @abstractmethod
    def parse(self, file_path):
        pass

    @abstractmethod
    def get_elasticsearch_mapping(self):
        pass

    def to_int(self, value, default=None):
        try:
            return int(str(value).strip())
        except (TypeError, ValueError) as e:
            logger.debug(f"to_int conversion failed for value '{value}': {e}")
            return default

    def to_float(self, value, default=None):
        try:
            return float(str(value).strip())
        except (TypeError, ValueError) as e:
            logger.debug(f"to_float conversion failed for value '{value}': {e}")
            return default

    def normalize_severity(self, text, fallback='INFO'):
        text = (text or '').strip().upper()
        if text in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            return text
        if text in self.SEVERITY_ALIASES:
            return self.SEVERITY_ALIASES[text]
        if text.isdigit():
            prio = self.to_int(text)
            if prio is not None:
                return self.severity_from_priority(prio)
        return fallback

    def _severity_to_int(self, severity_str):
        sev = (severity_str or '').strip().upper()
        if sev == 'CRITICAL':
            return 1
        if sev == 'HIGH':
            return 2
        if sev == 'MEDIUM':
            return 3
        if sev == 'LOW':
            return 4
        return 5

    def severity_from_priority(self, priority_value):
        priority = self.to_int(priority_value)
        if priority is None:
            return "INFO"
        sev_code = priority % 8
        if sev_code <= 2:
            return "CRITICAL"
        if sev_code == 3:
            return "HIGH"
        if sev_code == 4:
            return "MEDIUM"
        if sev_code == 5:
            return "LOW"
        return "INFO"

    def to_iso(self, date_str, default=None):
        try:
            raw = str(date_str).strip()
            parsed = date_parser.parse(raw)
            if not self._timestamp_has_explicit_year(raw):
                now = datetime.now(parsed.tzinfo) if parsed.tzinfo else datetime.now()
                future_threshold = now + timedelta(days=2)
                # Syslog timestamps often omit year; if parsing lands in the future,
                # roll back to the most recent plausible year.
                for _ in range(3):
                    if parsed <= future_threshold:
                        break
                    parsed = self._roll_back_one_year(parsed)
            return parsed.isoformat()
        except Exception as e:
            logger.debug(f"to_iso conversion failed for date_str '{date_str}': {e}")
            return default

    def _timestamp_has_explicit_year(self, value):
        text = str(value or "").strip()
        if not text:
            return False
        if re.search(r'(?<!\d)\d{4}(?!\d)', text):
            return True
        return bool(self.DATE_WITH_YEAR_REGEX.search(text))

    def _roll_back_one_year(self, dt):
        try:
            return dt.replace(year=dt.year - 1)
        except ValueError:
            # Handle leap day fallback for non-leap target years.
            return dt.replace(year=dt.year - 1, month=2, day=28)

    def normalize_timestamp(self, *candidates):
        for candidate in candidates:
            if candidate is None:
                continue
            value = str(candidate).strip()
            if not value:
                continue
            iso_val = self.to_iso(value)
            if iso_val:
                return iso_val
        for candidate in candidates:
            if candidate is None:
                continue
            value = str(candidate).strip()
            if value:
                return value
        return ""

    def clean_value(self, value):
        if isinstance(value, str):
            return value.strip().strip('"').strip("'")
        return value

    def build_record(self, **fields):
        cleaned_fields = {}
        for k, v in fields.items():
            if isinstance(v, str):
                cleaned_fields[k] = self.clean_value(v)
            else:
                cleaned_fields[k] = v
        return dict(cleaned_fields)

    def parse_syslog_prefix(self, line):
        text = (line or "").strip()
        for regex in self.SYSLOG_REGEXES:
            match = regex.match(text)
            if match:
                parsed = match.groupdict()
                parsed["payload"] = parsed.get("payload", "")
                return parsed
        return None

    def parse_json_line(self, text):
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                return {str(k).lower(): self.clean_value(v) for k, v in payload.items()}
        except Exception:
            return {}
        return {}

    def parse_kv_pairs(self, text):
        if not text:
            return {}
        pairs = {}
        for match in self.KV_REGEX.finditer(text):
            key = match.group("key").lower()
            value = self.clean_value(match.group("value"))
            pairs[key] = value
        return pairs

    def lower_keys(self, data):
        out = {}
        if not isinstance(data, dict):
            return out
        for key, value in data.items():
            out[str(key).lower()] = self.clean_value(value)
        return out

    def first_value(self, *values):
        for value in values:
            if value is None:
                continue
            if isinstance(value, str):
                cleaned = value.strip()
                if cleaned:
                    return cleaned
                continue
            return value
        return ""

    def dict_first(self, source, keys, default=""):
        if not isinstance(source, dict):
            return default
        lowered = source
        for key in keys:
            value = lowered.get(key.lower())
            if value is None:
                continue
            if isinstance(value, str):
                cleaned = value.strip()
                if cleaned:
                    return cleaned
            else:
                return value
        return default

    def normalize_ip(self, value):
        if value is None:
            return ""
        candidate = str(value).strip().strip('[](),')
        if not candidate:
            return ""

        if self.IPV4_REGEX.fullmatch(candidate):
            return candidate

        if ":" in candidate and candidate.count(":") == 1:
            left, right = candidate.split(":", 1)
            if self.IPV4_REGEX.fullmatch(left) and right.isdigit():
                return left

        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass

        match = self.IPV4_REGEX.search(candidate)
        if match:
            return match.group(0)
        return ""

    def normalize_port(self, value):
        port = self.to_int(value)
        if port is None:
            return None
        if 0 <= port <= 65535:
            return port
        return None

    def normalize_action(self, action_value, message=""):
        action = str(action_value or "").strip().lower().replace(" ", "_")
        if action in self.ACTION_ALIASES:
            return self.ACTION_ALIASES[action]

        text = f"{action} {message or ''}".lower()
        if any(word in text for word in ["deny", "drop", "block", "reject", "quarantine"]):
            return "deny"
        if any(word in text for word in ["allow", "accept", "permit", "pass"]):
            return "allow"
        if any(word in text for word in ["auth success", "login success", "authenticated"]):
            return "auth_success"
        if any(word in text for word in ["auth fail", "login fail", "authentication failed", "denied"]):
            return "auth_fail"
        if "logout" in text:
            return "logout"
        if "login" in text:
            return "login"
        return action

    def infer_outcome(self, action, message="", raw_fields=None):
        text = f"{action or ''} {message or ''}".lower()
        if isinstance(raw_fields, dict):
            status = self.dict_first(raw_fields, ["status", "result", "outcome", "disposition"])
            if status:
                text += f" {status}".lower()

        if any(word in text for word in ["deny", "drop", "block", "reject", "quarantine"]):
            return "blocked"
        if any(word in text for word in ["fail", "failed", "error", "invalid"]):
            return "failed"
        if any(word in text for word in ["allow", "accept", "permit", "pass"]):
            return "allowed"
        if any(word in text for word in ["success", "ok", "authenticated"]):
            return "success"
        if any(word in text for word in ["detect", "alert", "threat"]):
            return "detected"
        return "unknown"

    def infer_log_category(self, raw_fields=None, message="", event="", action="", default="unknown"):
        values = []
        if isinstance(raw_fields, dict):
            values.extend([
                self.dict_first(raw_fields, ["type", "subtype", "log_type", "event_type", "category", "module", "service"]),
                self.dict_first(raw_fields, ["appcat", "app", "signature", "threat", "attack", "proto"]),
            ])
        values.extend([event, action, message])
        text = " ".join(str(v or "") for v in values).lower()

        if any(word in text for word in ["threat", "intrusion", "ips", "ids", "attack", "exploit", "signature"]):
            return "threat"
        if any(word in text for word in ["malware", "virus", "spyware", "ransomware", "botnet", "c2"]):
            return "malware"
        if any(word in text for word in ["auth", "login", "logout", "mfa", "radius", "saml", "ldap", "user-id", "user id"]):
            return "authentication"
        if any(word in text for word in ["vpn", "ipsec", "ike", "sslvpn", "globalprotect", "tunnel"]):
            return "vpn"
        if any(word in text for word in ["system", "daemon", "kernel", "service", "resource", "health", "temperature", "fan", "cpu", "memory"]):
            return "system"
        if any(word in text for word in ["config", "policy install", "commit", "admin", "cli", "change", "audit"]):
            return "configuration"
        if any(word in text for word in ["dns", "domain", "resolver", "query", "response"]):
            return "dns"
        if any(word in text for word in ["url", "web", "http", "https", "proxy", "category"]):
            return "web"
        if any(word in text for word in ["nat", "session", "flow", "traffic", "forward", "packet", "connection", "firewall"]):
            return "traffic"
        if any(word in text for word in ["ha", "cluster", "failover", "sync"]):
            return "ha"
        if any(word in text for word in ["route", "bgp", "ospf", "rip", "static route"]):
            return "routing"
        if any(word in text for word in ["wireless", "wifi", "ssid", "ap "]):
            return "wireless"
        return default

    def infer_network_type(self, message="", raw_fields=None):
        text = str(message or "").lower()
        if isinstance(raw_fields, dict):
            text += " " + " ".join(str(v or "").lower() for v in raw_fields.values())
        if any(k in text for k in ["sslvpn", "nsvpn", "globalprotect", "vpn", "citrix gateway"]):
            return "sslvpn"
        if any(k in text for k in ["ike", "ipsec"]):
            return "ike"
        if "appfw" in text or "app firewall" in text:
            return "appfw"
        if "wan" in text or "internet" in text:
            return "wan"
        if "lan" in text or "intranet" in text:
            return "lan"
        if "dmz" in text:
            return "dmz"
        return "unknown"

    def infer_event(self, raw_fields=None, message="", fallback="unknown"):
        if isinstance(raw_fields, dict):
            for key in [
                "event", "event_type", "subtype", "log_subtype", "attack", "signature",
                "threat", "msgid", "messageid", "id", "operation", "action"
            ]:
                value = self.dict_first(raw_fields, [key])
                if value:
                    return str(value)
        text = str(message or "").strip()
        if not text:
            return fallback
        words = text.split()
        return " ".join(words[:6])

    def enrich_record(self, record, vendor="", default_category="unknown"):
        rec = dict(record or {})
        raw_fields = self.lower_keys(rec.get("raw_fields") or {})

        payload_message = self.first_value(
            rec.get("message"),
            self.dict_first(raw_fields, ["msg", "message", "description", "reason", "details"]),
            ""
        )

        date_part = self.dict_first(raw_fields, ["date", "logdate", "eventdate", "devdate"])
        time_part = self.dict_first(raw_fields, ["time", "eventtime", "devtime"])
        dt_compound = f"{date_part} {time_part}".strip() if date_part or time_part else ""

        timestamp = self.normalize_timestamp(
            rec.get("timestamp"),
            dt_compound,
            self.dict_first(raw_fields, ["timestamp", "event_time", "generated_time", "receive_time", "time_generated", "starttime"]),
            self.dict_first(raw_fields, ["rt"]),
        )

        severity_candidate = self.first_value(
            rec.get("severity"),
            self.dict_first(raw_fields, ["severity", "level", "risk", "threatlevel", "priority", "pri"]),
            rec.get("syslog_priority"),
        )
        severity = self.normalize_severity(
            severity_candidate,
            fallback=self.severity_from_priority(rec.get("syslog_priority")) if rec.get("syslog_priority") is not None else "INFO",
        )

        host = self.first_value(
            rec.get("host"),
            rec.get("syslog_host"),
            self.dict_first(raw_fields, ["host", "hostname", "device", "device_name", "devname"]),
        )

        src_ip = self.normalize_ip(self.first_value(
            rec.get("src_ip"),
            rec.get("srcip"),
            self.dict_first(raw_fields, ["src", "srcip", "src_ip", "source", "source_ip", "sip", "clientip", "client_ip"]),
        ))
        dst_ip = self.normalize_ip(self.first_value(
            rec.get("dst_ip"),
            rec.get("dstip"),
            self.dict_first(raw_fields, ["dst", "dstip", "dst_ip", "destination", "destination_ip", "dip", "serverip", "server_ip"]),
        ))

        if not src_ip:
            msg_src = re.search(r'\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b', payload_message, re.IGNORECASE)
            if msg_src:
                src_ip = msg_src.group(1)
        if not dst_ip:
            msg_dst = re.search(r'\bto\s+((?:\d{1,3}\.){3}\d{1,3})\b', payload_message, re.IGNORECASE)
            if msg_dst:
                dst_ip = msg_dst.group(1)

        src_port = self.normalize_port(self.first_value(
            rec.get("src_port"),
            rec.get("srcport"),
            self.dict_first(raw_fields, ["srcport", "sport", "spt", "source_port"]),
        ))
        dst_port = self.normalize_port(self.first_value(
            rec.get("dst_port"),
            rec.get("dstport"),
            self.dict_first(raw_fields, ["dstport", "dport", "dpt", "destination_port"]),
        ))

        protocol = str(self.first_value(
            rec.get("protocol"),
            self.dict_first(raw_fields, ["proto", "protocol", "service", "transport"]),
        )).upper()

        action = self.normalize_action(
            self.first_value(
                rec.get("action"),
                rec.get("palo_action"),
                self.dict_first(raw_fields, ["action", "act", "result", "status", "disposition", "verdict", "operation"]),
            ),
            payload_message,
        )

        event = self.first_value(
            rec.get("event"),
            rec.get("event_type"),
            self.infer_event(raw_fields=raw_fields, message=payload_message),
        )

        log_category = self.first_value(
            rec.get("log_category"),
            rec.get("category"),
            self.infer_log_category(
                raw_fields=raw_fields,
                message=payload_message,
                event=event,
                action=action,
                default=default_category,
            ),
            default_category,
        )

        outcome = self.first_value(
            rec.get("outcome"),
            self.infer_outcome(action=action, message=payload_message, raw_fields=raw_fields),
        )

        user = self.first_value(
            rec.get("user"),
            self.dict_first(raw_fields, ["user", "username", "srcuser", "dstuser", "admin", "account", "userid", "user_id"]),
        )

        rule = self.first_value(
            rec.get("rule"),
            rec.get("policy"),
            self.dict_first(raw_fields, ["rule", "rulename", "policy", "policyid", "policyname", "acl", "access_rule"]),
        )

        signature = self.first_value(
            rec.get("signature"),
            self.dict_first(raw_fields, ["signature", "attack", "threat", "sig", "sig_name", "ips_signature"]),
        )

        event_id = self.first_value(
            rec.get("event_id"),
            self.dict_first(raw_fields, ["eventid", "event_id", "id", "logid", "msgid", "messageid", "sid"]),
        )

        session_id = self.first_value(
            rec.get("session_id"),
            rec.get("sessionid"),
            self.dict_first(raw_fields, ["sessionid", "session_id", "connection_id", "connid", "flowid", "sid"]),
        )

        network_type = self.first_value(
            rec.get("network_type"),
            self.infer_network_type(payload_message, raw_fields=raw_fields),
        )

        rec.update(
            self.build_record(
                vendor=vendor or rec.get("vendor", ""),
                timestamp=timestamp,
                severity=severity,
                severity_int=self._severity_to_int(severity),
                host=host,
                message=payload_message,
                event=event,
                log_category=log_category,
                action=action,
                outcome=outcome,
                user=user,
                rule=rule,
                signature=signature,
                event_id=str(event_id) if event_id is not None else "",
                session_id=str(session_id) if session_id is not None else "",
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                srcip=src_ip,
                dstip=dst_ip,
                srcport=src_port,
                dstport=dst_port,
                network_type=network_type,
                raw_fields=raw_fields,
            )
        )
        return rec

    def get_base_elasticsearch_mapping(self):
        return {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "vendor": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "severity_int": {"type": "integer"},
                    "log_category": {"type": "keyword"},
                    "event": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "outcome": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "rule": {"type": "keyword"},
                    "signature": {"type": "keyword"},
                    "event_id": {"type": "keyword"},
                    "session_id": {"type": "keyword"},
                    "protocol": {"type": "keyword"},
                    "network_type": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "src_port": {"type": "integer"},
                    "dst_port": {"type": "integer"},
                    "srcip": {"type": "ip"},
                    "dstip": {"type": "ip"},
                    "srcport": {"type": "integer"},
                    "dstport": {"type": "integer"},
                    "message": {"type": "text"},
                    "raw_fields": {"type": "object", "enabled": True}
                }
            }
        }
