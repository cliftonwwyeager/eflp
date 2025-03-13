from abc import ABC, abstractmethod
from dateutil import parser as date_parser

class BaseParser(ABC):
    @abstractmethod
    def parse(self, file_path):
        pass

    @abstractmethod
    def get_elasticsearch_mapping(self):
        pass

    def to_int(self, value, default=None):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def normalize_severity(self, text, fallback='INFO'):
        text = (text or '').strip().upper()
        if text in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            return text
        return fallback

    def _severity_to_int(self, severity_str):
        sev = (severity_str or '').strip().upper()
        if sev == 'CRITICAL':
            return 1
        elif sev == 'HIGH':
            return 2
        elif sev == 'MEDIUM':
            return 3
        elif sev == 'LOW':
            return 4
        else:
            return 5

    def to_iso(self, date_str, default=None):
        try:
            return date_parser.parse(date_str).isoformat()
        except Exception:
            return default

    def build_record(self, **fields):
        return dict(fields)
