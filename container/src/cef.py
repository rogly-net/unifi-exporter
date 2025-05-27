import src.core as core
import re

class Cef:
    """
    Handles Common Event Format (CEF) messages.

    This class provides utilities for parsing CEF messages, mapping fields, 
    and exporting the parsed data to Loki. It includes methods for extracting 
    and validating CEF fields, converting severity levels, and handling syslog 
    headers.

    Attributes:
        core (Core): Utility instance for logging and regex operations.
        map (Map): Utility for mapping CEF fields and severity levels.
        loki (LokiExporter): Instance for exporting parsed data to Loki.
        record (dict): Container for storing parsed field values.
        labels (dict): Container for storing parsed label key-value pairs.
    """

    def __init__(self):
        """
        Initializes the Cef class.

        This constructor sets up the core utilities for logging and regex operations,
        initializes the field mapping and Loki exporter instances, and prepares
        containers for storing parsed field values and labels.
        """
        self.core = core.Core()
        self.map = core.Map()
        self.loki = core.LokiExporter()
        self.record = {}
        self.labels = {}

    class Fields:
        """
        Represents a container for parsed CEF fields and their corresponding labels.

        This inner class is used to encapsulate the extracted field values and 
        label key-value pairs after parsing a CEF message.

        Attributes:
            record (dict): A dictionary containing the extracted field values 
            from the CEF message.
            labels (dict): A dictionary containing the label key-value pairs 
            derived from the CEF message headers.
        """

        def __init__(self, record: dict = None, labels: dict = None):
            """
            Initializes the Fields class.

            This constructor sets up the Fields class with the provided record
            and labels dictionaries, which store the extracted field values
            and label key-value pairs from a parsed CEF message.

            Args:
                record (dict, optional): A dictionary containing the extracted 
                field values from the CEF message. Defaults to None.
                labels (dict, optional): A dictionary containing the label 
                key-value pairs derived from the CEF message headers. Defaults to None.
            """
            self.record = record
            self.labels = labels
    
    def fields(self, message: str, record: dict, labels: dict) -> Fields:
        """
        Parses a CEF message into structured fields and labels.

        This method processes a raw CEF message, splitting it into its 
        constituent parts, mapping the fields to predefined labels, and 
        extracting the message body. It also validates the message format 
        and converts severity levels to human-readable formats.

        Args:
            message (str): The raw CEF message to parse.
            record (dict): A dictionary to store the extracted field values.
            labels (dict): A dictionary to store the extracted label key-value pairs.

        Returns:
            Fields: An instance of the Fields class containing the parsed 
            fields and labels, or None if parsing fails due to an invalid 
            message format or missing fields.
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
        Parses a syslog+CEF message and exports it to Loki.

        This method processes a raw syslog+CEF message by extracting the 
        timestamp and hostname from the syslog header, parsing the CEF fields 
        into structured data, and exporting the parsed information to Loki.

        Args:
            message (str): The raw syslog+CEF message to be processed.
            cached_ip (str): The cached IP address used for exporting data.

        Returns:
            tuple: A tuple containing the updated cached IP address and a 
            boolean indicating whether the export to Loki was successful.
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
