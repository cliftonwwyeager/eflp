from abc import ABC, abstractmethod
from dateutil import parser as date_parser
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

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
        except (TypeError, ValueError) as e:
            logger.debug(f"to_int conversion failed for value '{value}': {e}")
            return default

    def to_float(self, value, default=None):
        try:
            return float(value)
        except (TypeError, ValueError) as e:
            logger.debug(f"to_float conversion failed for value '{value}': {e}")
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
        except Exception as e:
            logger.debug(f"to_iso conversion failed for date_str '{date_str}': {e}")
            return default

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
