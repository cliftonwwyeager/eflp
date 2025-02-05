from dateutil import parser as date_parser

class MerakiParser:
    def parse(self, file_path):
        parsed_logs = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                log_entry = {}
                tokens = line.split()
                for token in tokens:
                    if '=' in token:
                        key, value = token.split("=", 1)
                        log_entry[key.strip()] = value.strip().
                if 'timestamp' in log_entry:
                    try:
                        log_entry['timestamp'] = date_parser.parse(log_entry['timestamp']).isoformat()
                    except Exception:
                        pass
                parsed_logs.append(log_entry)
        return parsed_logs

    def get_elasticsearch_mapping(self):
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "src_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "protocol": {"type": "keyword"},
                    "src_port": {"type": "integer"},
                    "dest_port": {"type": "integer"},
                    "action": {"type": "keyword"}
                }
            }
        }
        return mapping
