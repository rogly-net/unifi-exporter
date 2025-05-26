import src.core as core
import re

class Cef:
    """
    Handles Common Event Format (CEF) messages.

    This class provides methods to map fields, parse messages, and export
    parsed data to Loki.

    Attributes:
        core (Core): Logging and regex utility instance.
        map (Map): Field mapping utility.
        loki (LokiExporter): Loki exporter instance.
        record (dict): Parsed record container.
        labels (dict): Parsed labels container.
    """

    def __init__(self):
        """
        Initializes the Cef class.

        Initializes the core utilities, field mapping, Loki exporter, and
        containers for parsed data.
        """
        self.core = core.Core()
        self.map = core.Map()
        self.loki = core.LokiExporter()
        self.record = {}
        self.labels = {}

    class Fields:
        """
        Container for parsed fields and corresponding labels.

        Attributes:
            record (dict): Extracted field values.
            labels (dict): Label key-value pairs.
        """

        def __init__(self, record: dict = None, labels: dict = None):
            """
            Initializes the Fields class.

            Args:
                record (dict, optional): Extracted field values. Defaults to None.
                labels (dict, optional): Label key-value pairs. Defaults to None.
            """
            self.record = record
            self.labels = labels
    
    def fields(self, message: str, record: dict, labels: dict) -> Fields:
        """
        Parses a CEF message into fields and extracts the message text.

        Args:
            message (str): The CEF message to parse.
            record (dict): The dictionary to store parsed field values.
            labels (dict): The dictionary to store parsed label key-value pairs.

        Returns:
            Fields: An instance of the Fields class containing parsed fields
            and labels, or None if parsing fails.
        """
        self.core.logger("debug", "cef", "fields", f"Parsing CEF message: {message}")
        
        # Split header on pipe delimiter
        fields = message.split("|")
        self.core.logger("debug", "cef", "fields", f"Split message into fields: {fields}")

        # If only 7 segments, insert placeholder for missing field
        if len(fields) == 7:
            fields.insert(5, "missing")
            self.core.logger("debug", "cef", "fields", "Inserted placeholder for missing field.")

        # Validate we have exactly 8 segments now, else fail
        if len(fields) != 8:
            self.core.logger("error", "cef", "fields", f"Invalid CEF message format: {message}")
            return
        
        # Map each segment: first 7 become labels, 8th is the message body
        for i in range(len(fields)):
            field_name = self.map.cef(i)
            if field_name:
                if i < 7:
                    # standard headers → labels
                    labels[field_name] = fields[i]
                    self.core.logger("debug", "cef", "fields", f"Mapped label {field_name}: {fields[i]}")

                if i == 7:
                    # extension segment → record["message"]
                    record["message"] = fields[i]
                    self.core.logger("debug", "cef", "fields", f"Mapped message body: {fields[i]}")

                if field_name == "severity":
                    # convert numeric severity to human level
                    labels["level"] = self.map.severity("cef", int(fields[i]))
                    self.core.logger("debug", "cef", "fields", f"Converted severity {fields[i]} to level: {labels['level']}")

        # Extract the 'msg=' part from the extension
        if record.get("message"):
            match = self.core.extract(record["message"], r"msg=(.*)", 1)
            self.core.logger("debug", "cef", "fields", f"Extracted message: {match.value if match.value else 'None'}")
            
            if match.value:
                record["message"] = match.value
            else:
                self.core.logger("error", "cef", "fields",
                                f"Message extraction failed: {record['message']}")
                return
        else:
            self.core.logger("error", "cef", "fields", f"No message field found in: {message}")
            return
        return self.Fields(record, labels)

    def parse(self, message: str, cached_ip: str) -> tuple:
        """
        Parses a full syslog+CEF message and exports it to Loki.

        This method extracts the timestamp and hostname from the syslog header,
        parses the CEF fields, and exports the parsed data to Loki.

        Args:
            message (str): The raw syslog+CEF message to parse.

        Returns:
            bool: True if the message was successfully exported to Loki,
            False otherwise.
        """
        self.labels["type"] = "cef"
        self.core.logger("debug", "cef", "parse", f"Starting to parse message: {message}")

        # Extract timestamp (e.g., "Jan  1 12:34:56")
        timestamp = self.core.extract(message, r"^([A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2})", 1)
        self.core.logger("debug", "cef", "parse", f"Extracted timestamp: {timestamp.value if timestamp.value else 'None'}")
        
        if timestamp:
            # check for second timestamp in the message
            second_timestamp = self.core.extract(timestamp.cleaned, r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z)", 1)
            if second_timestamp:
                timestamp = second_timestamp

            # Extract hostname before the "CEF:" marker
            hostname = self.core.extract(timestamp.cleaned, r"^(.+)\sCEF:", 1)
            self.core.logger("debug", "cef", "parse", f"Extracted hostname: {hostname.value if hostname.value else 'None'}")
            
            if hostname:
                self.labels["hostname"] = self.labels["hostname"] = re.sub(r"\s", "-", hostname.value)
                self.core.logger("debug", "cef", "parse", f"Set hostname label: {self.labels['hostname']}")
                
                # Parse individual CEF fields & extension
                fields = self.fields(hostname.cleaned, self.record, self.labels)
                if fields:
                    self.core.logger("debug", "cef", "parse", f"Parsed fields: {fields.record}, labels: {fields.labels}")
                    
                    # Export final record to Loki
                    cached_ip, result = self.loki.export(fields.record, fields.labels, timestamp.value, cached_ip)
                    self.core.logger("debug", "cef", "parse", f"Export status: {'Success' if result else 'Failure'}")
                    return cached_ip, result
            else:
                self.core.logger("error", "cef", "parse",
                                f"Hostname missing in message: {message}")
                return cached_ip, False
        
        else:
            self.core.logger("error", "cef", "parse",
                            f"Timestamp missing in message: {message}")
            return cached_ip, False
