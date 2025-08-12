import re
import uuid
from datetime import datetime
from dateutil import parser as date_parser

_IP = r'(?:\d{1,3}\.){3}\d{1,3}'
_IP_PORT = rf'(?P<ip>{_IP})(?::(?P<port>\d+))?'

_SYSLOG_RE = re.compile(
    r'^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<tag>[\w\-/\[\]\.:]+)\s*:\s*(?P<msg>.*)$'
)

_KV_RE = re.compile(r'(?P<key>[A-Za-z_][A-Za-z0-9_\-]*)=(?P<val>"[^"]*"|\S+)')
_FROM_IP_RE = re.compile(r'\bfrom\s+(?P<ip>' + _IP + r')\b', re.IGNORECASE)
_TO_IP_RE   = re.compile(r'\bto\s+(?P<ip>' + _IP + r')\b', re.IGNORECASE)
_ARROW_IPS  = re.compile(r'(?P<src>' + _IP + r')\s*->\s*(?P<dst>' + _IP + r')')
_ALLOW_WORDS = re.compile(r'\b(allow|accept|permit)\b', re.IGNORECASE)
_DENY_WORDS  = re.compile(r'\b(deny|blocked?|drop(ped)?)\b', re.IGNORECASE)
_AUTH_OK     = re.compile(r'\b(auth|login)\s+(success|ok)\b', re.IGNORECASE)
_AUTH_FAIL   = re.compile(r'\b(auth|login)\s+(fail|den(y|ied))\b', re.IGNORECASE)

def _clean(val: str) -> str:
    if isinstance(val, str) and len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        return val[1:-1]
    return val

def _infer_network_type(tag: str, msg: str) -> str:
    s = f"{tag or ''} {msg or ''}".lower()
    if 'sslvpn' in s or 'nsvpn' in s or 'vpn' in s or 'citrix gateway' in s:
        return 'sslvpn'
    if 'ike' in s or 'ipsec' in s:
        return 'ike'
    if 'appfw' in s or 'app firewall' in s:
        return 'appfw'
    if 'wan' in s or 'internet' in s:
        return 'wan'
    if 'lan' in s or 'intranet' in s:
        return 'lan'
    if 'dmz' in s:
        return 'dmz'
    return 'unknown'

def _infer_action(msg: str) -> str:
    if not msg:
        return ''
    if _ALLOW_WORDS.search(msg):
        return 'allow'
    if _DENY_WORDS.search(msg):
        return 'deny'
    if _AUTH_OK.search(msg):
        return 'auth_success'
    if _AUTH_FAIL.search(msg):
        return 'auth_fail'
    return ''

def _extract_ips_ports(msg: str, kv: dict) -> tuple[str, str, str, str]:
    src_ip = kv.get('src') or kv.get('srcip') or kv.get('clientip') or kv.get('client_ip') or kv.get('sip') or ''
    dst_ip = kv.get('dst') or kv.get('dstip') or kv.get('dip') or kv.get('serverip') or ''
    src_port = kv.get('sport') or kv.get('spt') or ''
    dst_port = kv.get('dport') or kv.get('dpt') or ''
    if not src_ip:
        m = re.search(_IP_PORT, msg)
        if m:
            src_ip = m.group('ip') or ''
            if not src_port and m.group('port'):
                src_port = m.group('port')
    if (not src_ip or not dst_ip) and msg:
        m = _ARROW_IPS.search(msg)
        if m:
            src_ip = src_ip or m.group('src')
            dst_ip = dst_ip or m.group('dst')
    if not src_ip and msg:
        m = _FROM_IP_RE.search(msg)
        if m:
            src_ip = m.group('ip')
    if not dst_ip and msg:
        m = _TO_IP_RE.search(msg)
        if m:
            dst_ip = m.group('ip')
    return src_ip, dst_ip, src_port, dst_port

def _extract_event(tag: str, msg: str, kv: dict) -> str:
    for k in ('event', 'eventname', 'signature', 'sig', 'attack', 'policyname', 'policy', 'profile'):
        if kv.get(k):
            return _clean(str(kv.get(k)))
    m = re.search(r'\b(APPFW_[A-Z_0-9]+)\b', msg or '')
    if m:
        return m.group(1)
    if tag:
        return tag
    if msg:
        return ' '.join(msg.split()[:5])
    return 'unknown'

class NetscalerParser:
    VENDOR = "netscaler"

    def parse(self, file_path: str):
        out = []
        with open(file_path, 'r', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                ts = ''
                severity = ''
                host = ''
                tag = ''
                msg = line
                m = _SYSLOG_RE.match(line)
                if m:
                    ts = m.group('ts') or ''
                    host = m.group('host') or ''
                    tag = (m.group('tag') or '').strip()
                    msg = (m.group('msg') or '').strip()
                    
                kv = {k.lower(): _clean(v) for k, v in _KV_RE.findall(line)}
                iso_ts = ''
                for candidate in (ts, kv.get('time'), kv.get('timestamp'), kv.get('date'), line):
                    if not candidate:
                        continue
                    try:
                        iso_ts = date_parser.parse(candidate, fuzzy=True).isoformat()
                        break
                    except Exception:
                        continue
                severity = kv.get('severity', kv.get('level', kv.get('pri', ''))).lower() if kv else ''
                if not severity and tag:
                    if '.' in tag:
                        severity = tag.split('.')[-1].lower()
                src_ip, dst_ip, src_port, dst_port = _extract_ips_ports(line, kv)
                protocol = kv.get('proto') or kv.get('protocol') or ''
                action = _infer_action(line)
                event = _extract_event(tag, msg, kv)
                network_type = _infer_network_type(tag, msg)
                record = {
                    "timestamp": iso_ts or '',
                    "severity": severity or '',
                    "message": msg,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "action": action,
                    "event": event,
                    "network_type": network_type,
                    "subtype": kv.get('subtype', ''),
                    "object": kv.get('policy') or kv.get('policyname') or kv.get('profile') or '',
                    "host": host,
                    "vendor": self.VENDOR,
                    "record_id": str(uuid.uuid4()),
                    "event_id": kv.get('eventid', kv.get('id', ''))
                }
                out.append(record)
        return out

    def get_elasticsearch_mapping(self):
        return {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "severity":  {"type": "keyword"},
                    "message":   {"type": "text"},
                    "src_ip":    {"type": "ip"},
                    "dst_ip":    {"type": "ip"},
                    "src_port":  {"type": "integer"},
                    "dst_port":  {"type": "integer"},
                    "protocol":  {"type": "keyword"},
                    "action":    {"type": "keyword"},
                    "event":     {"type": "keyword"},
                    "network_type": {"type": "keyword"},
                    "subtype":   {"type": "keyword"},
                    "object":    {"type": "keyword"},
                    "host":      {"type": "keyword"},
                    "vendor":    {"type": "keyword"},
                    "record_id": {"type": "keyword"},
                    "event_id":  {"type": "keyword"}
                }
            }
        }
