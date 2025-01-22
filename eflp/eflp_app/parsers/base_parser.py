from abc import ABC, abstractmethod

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
        if text in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']:
            return text
        return fallback

    def build_record(self, **fields):
        return dict(fields)