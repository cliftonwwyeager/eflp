from dateutil import parser as date_parser

class MerakiParser:
    def parse(self, file_path):
        """
        Parse Meraki firewall traffic logs.
        Assumes each log line is a series of key=value pairs separated by whitespace.
        Example log line:
        timestamp=2021-02-01T12:34:56Z src_ip=192.168.1.1 dest_ip=10.0.0.1 protocol=TCP src_port=12345 dest_port=80 action=allow
        """
        parsed_logs = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                log_entry = {}
                # Split the line into tokens and then into key/value pairs.
                tokens = line.split()
                for token in tokens:
                    if '=' in token:
                        key, value = token.split("=", 1)
                        log_entry[key.strip()] = value.strip()
                # If a timestamp is present, try to normalize it.
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
