from types import FrameType
import threading
import socket
import datetime
import os
import pytz
import json
import re
import requests
import tarfile
import ipaddress
import geoip2.database

class Core:
    """
    Core class for the application.

    This class provides essential utilities and functionality for the application, including:
    - Logging with customizable log levels and thread identification.
    - Environment variable validation to ensure required variables are set.
    - Signal handling for graceful application shutdown (e.g., SIGTERM).
    - Data extraction using regular expressions with support for cleaned messages.
    - Application state management through a stop flag for controlled termination.
    - Error handling and reporting to assist in debugging and operational stability.

    It serves as a foundational component for building robust and maintainable applications.
    """
    def __init__(self):
        """
        Initializes the Core class.

        This constructor sets up the default attributes for the Core class, including:
        - Metadata such as name, version, description, author, and email.
        - A stop flag to manage application termination gracefully.

        It serves as the foundational setup for the Core utilities.
        """
        self._name = "CoreUtilities"
        self._version = "1.0.0"
        self._description = "Core utilities for the application."
        self._author = "Rogly"
        self._email = "rogly@rogly.net"
        self.stop_flag = False

    class Extracted:
        """
        Represents data extracted from a message.

        This class encapsulates:
        - `value`: The extracted value from the message.
        - `original`: The original message from which the value was extracted.
        - `cleaned`: The message after the extracted value has been removed.

        It provides a structured way to handle and represent extracted data.
        """
        def __init__(self, value: str = None, original: str = None, cleaned: str = None):
            """
            Initializes an instance of the Extracted class.

            Args:
                value (str, optional): The value extracted from the message. Defaults to None.
                original (str, optional): The original message from which the value was extracted. Defaults to None.
                cleaned (str, optional): The message after the extracted value has been removed. Defaults to None.
            """
            self.value = value
            self.original = original
            self.cleaned = cleaned
        def __str__(self):
            """
            Returns:
                str: A string representation of the Extracted object. This includes:
                - The extracted value (`value`).
                - The original message (`original`).
                - The cleaned message (`cleaned`), which is the original message with the extracted value removed.
            """
            return f"Extracted(value={self.value}, original={self.original}, cleaned={self.cleaned})"

    def logger(self, level: str, program: str, function: str, message: str) -> None:
        """
        Logs a message with the specified level, program, function, and message.

        This method formats the log message with a timestamp, thread name, and 
        the provided details, and prints it to the console. It respects the 
        log level set in the environment variable `LOG_LEVEL` to filter messages.

        Args:
            level (str): The log level (e.g., "informational", "ERROR"). 
                 Supported levels are "debug", "informational", "warning", 
                 "error", and "critical".
            program (str): The name of the program or module generating the log.
            function (str): The name of the function generating the log.
            message (str): The log message to be recorded.

        Returns:
            None: This method does not return a value.
        """
        try:
            level = level.lower()
            system_log_level = os.getenv("LOG_LEVEL", "informational").lower()
            thread_name = threading.current_thread().name
            if "(" in thread_name:
                thread_name = re.search(r"\((.+)\)", thread_name).group(1).capitalize()
            # Check if the log level is set to a level that should be logged
            log_levels = ["debug", "informational", "warning", "error", "critical"]
            if log_levels.index(level) < log_levels.index(system_log_level):
                return  # Skip logging if the level is lower than the set log level

            # Log the message with a timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            # Handle any exceptions that occur during logging
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} - [ERROR][core][logger] - Error logging message: {e}")
            return
        
        print(f"{timestamp} - [{thread_name}] | [{level.upper()}][{program.upper()}][{function.upper()}]: {message}")

    def environment(self, env_vars: list) -> bool:
        """
        Validates the presence of required environment variables.

        This method checks if all the specified environment variables are set
        in the operating system's environment. If any variable is missing, it
        logs a critical error and terminates the application.

        Args:
            env_vars (list): A list of strings representing the names of the required environment variables.

        Returns:
            bool: Returns True if all required environment variables are set, otherwise exits the application.
        """
        for var in env_vars:
            if var not in os.environ:
                self.logger("critical", "core", "checl_environment", f"Environment variable {var} is not set.")
                exit(1)
        
        return True
    
    def sigterm(self, signum: int, frame: FrameType) -> None:
        """
        Handles the SIGTERM signal to gracefully shut down the application.

        This method is triggered when the application receives a SIGTERM signal,
        allowing it to perform cleanup tasks and set the stop flag to indicate
        that the application should terminate.

        Args:
            signum (int): The signal number received (e.g., SIGTERM).
            frame (FrameType): The current stack frame, useful for debugging purposes.

        Returns:
            None: This function does not return a value.
        """
        self.logger("critical", "core", "sigterm", f"Received SIGTERM [{signum}], shutting down syslog server...")
        self.logger("debug", "core", "sigterm", f"Signal frame: {frame}")
        self.stop_flag = True

    def extract(self, message: str, regex: str, group: int = 0) -> Extracted:
        """
        Extracts a value from a message using the provided regex pattern.

        This method searches the input message for a match to the given regular
        expression pattern. If a match is found, it extracts the specified capture
        group, removes the matched text from the original message, and returns
        an Extracted object containing the extracted value, the original message,
        and the cleaned message.

        Args:
            message (str): The input text to search.
            regex (str): The regular expression pattern to match.
            group (int, optional): The capture group index to extract. Defaults to 0.

        Returns:
            Extracted: An Extracted object containing:
            - value (str): The matched substring, or None if no match is found.
            - original (str): The original input message.
            - cleaned (str): The message with the matched text removed, or the
              original message if no match is found.
        """
        try:
            match = re.search(regex, message)
            if match:
                value = match.group(group)
                cleaned = re.sub(rf"{regex}", "", message).strip()
                return self.Extracted(value=value, original=message, cleaned=cleaned)
            else:
                return None
        except Exception as e:
            self.logger("error", "core", "extract", f"Error matching regex r\"{regex}\": {e}")
            return self.Extracted()

class Map:
    """
    Map utilities for translating numeric and coded values into human-readable formats.

    This class provides methods to:
        - priority(priority: str) -> Priority:
            Convert a syslog priority number into its facility and severity components.
        - severity(type: str, severity: int) -> str:
            Translate a syslog or CEF severity level into a textual description.
        - facility(facility: int) -> str:
            Translate a syslog facility code into its corresponding name.
        - protocol(protocol: int) -> str:
            Map an IP protocol number to its protocol name.
        - cef(field: int) -> str:
            Map a CEF field index to its corresponding field name.
        - ip(ip: str) -> str:
            Resolve an IP address to its hostname via reverse DNS lookup, or return the IP if resolution fails.
        - flow(flow: str) -> str:
            Translate a flow type identifier into a descriptive name.
        - portforward(rule: str) -> str:
            Map a port forwarding rule string to a human-readable rule name.

    Each method reads from its respective JSON configuration file under the `config/` directory.
    If a mapping is not found, the method returns "unknown" or the original input value.
    """
    def __init__(self):
        """
        Initializes the Map class.

        This constructor sets up the Map class by loading various mapping configurations
        from JSON files located in the 'config' directory. These mappings are used to
        translate numeric or coded values into human-readable formats.

        The following JSON files are validated and loaded:
          - syslog_severity.json: Maps syslog severity levels to descriptive labels.
          - cef_severity.json: Maps CEF severity levels to descriptive labels.
          - facilities.json: Maps syslog facility codes to descriptive labels.
          - ip_protocols.json: Maps IP protocol numbers to protocol names.
          - cef_fields.json: Maps CEF field indices to field names.
          - flow_fields.json: Maps flow type identifiers to descriptive names.
          - portforward_rules.json: Maps port forwarding rule strings to human-readable names.

        If any of these files or the 'config' directory is missing, the application
        logs a critical error and terminates.
        """
        self._name = "Maps"
        self._version = "1.0.0"
        self._description = "Maps for the application."
        self._author = "Rogly"
        self._email = "rogly@rogly.net"

        # Validate the configuration directory
        if not os.path.exists("config"):
            Core().logger("critical", "Map", "init", "Configuration directory 'config' not found.")
            exit(1)
        if not os.path.exists("config/syslog_severity.json"):
            Core().logger("critical", "Map", "init", "Configuration file 'syslog_severity.json' not found.")
            exit(1)
        if not os.path.exists("config/cef_severity.json"):
            Core().logger("critical", "Map", "init", "Configuration file 'cef_severity.json' not found.")
            exit(1)
        if not os.path.exists("config/facilities.json"):
            Core().logger("critical", "Map", "init", "Configuration file 'facilities.json' not found.")
            exit(1)
        if not os.path.exists("config/ip_protocols.json"):
            Core().logger("critical", "Map", "init", "Configuration file 'ip_protocols.json' not found.")
            exit(1)
        if not os.path.exists("config/cef_fields.json"):
            Core().logger("critical", "Map", "init", "Configuration file 'cef_fields.json' not found.")
            exit(1)
        if not os.path.exists("config/flow_fields.json"):
            Core().logger("critical", "Map", "init", "Configuration file 'flow_fields.json' not found.")
            exit(1)
        if not os.path.exists("config/portforward_rules.json"):
            Core().logger("critical", "Map", "init", "Configuration file 'portforward_rules.json' not found.")
            exit(1)

    class Priority:
        """
        Represents a syslog priority, encapsulating its
        facility and severity components.

        This class provides a structured representation of a syslog priority,
        which is a combination of a facility code and a severity level.

        Attributes:
            facility (int): The syslog facility code, representing the source
            of the log message (e.g., kernel, user-level, mail system).
            severity (int): The syslog severity level, indicating the importance
            or urgency of the log message (e.g., debug, informational, critical).
        """
        def __init__(self, facility: int, severity: int):
            """
            Initializes a Priority object representing a syslog priority.

            Args:
                facility (int): The syslog facility code, indicating the source of the log message 
                                (e.g., kernel, user-level, mail system). Valid range: 0–23.
                severity (int): The syslog severity level, indicating the importance or urgency of 
                                the log message (e.g., debug, informational, critical). Valid range: 0–7.
            """
            self.facility = facility
            self.severity = severity

        def __repr__(self):
            """
            Returns:
                str: A string representation of the Priority instance, 
                including its facility and severity components.
            """
            return f"Priority(facility={self.facility}, severity={self.severity})"

    def priority(self, priority: str) -> Priority:
        """
        Converts a syslog priority value into its facility and severity components.

        The syslog priority is a single numeric value that encodes both the facility
        (source of the log message) and the severity (importance level) of the log.
        This method decodes the priority into its constituent parts.

        Args:
            priority (str): The numeric syslog priority as a string or integer.
                    The value should be between 0 and 191, inclusive.

        Returns:
            Priority: An instance of the Priority class containing:
                  - `facility` (int): The facility code (0–23).
                  - `severity` (int): The severity level (0–7).
        """
        facility = int(priority) // 8
        severity = int(priority) % 8
        return self.Priority(facility, severity)

    def severity(self, type: str, severity: int) -> str:
        """
        Translate a numeric severity code to its human-readable label.

        This method supports two types of severity mappings:
          - "syslog": Maps syslog severity levels to descriptive labels using 'config/syslog_severity.json'.
          - "cef": Maps Common Event Format (CEF) severity levels to descriptive labels using 'config/cef_severity.json'.

        Args:
            type (str): The mapping type, either "syslog" or "cef".
            severity (int): The numeric severity value to translate.

        Returns:
            str: The corresponding severity description if found, or "unknown" if the value
             or mapping type is not recognized or not found in the configuration files.
        """
        # Load the syslog severity mappings from a JSON file
        try: 
            with open('config/syslog_severity.json') as syslog_severity:
                syslog = json.load(syslog_severity)
        except FileNotFoundError as e:
            Core().logger("critical", "Map", "severity", f"Syslog severity mapping file not found: {e}")
            exit(1)
        except json.JSONDecodeError as e:
            Core().logger("critical", "Map", "severity", f"Error decoding syslog severity mapping file: {e}")
            exit(1)
        except Exception as e:
            Core().logger("critical", "Map", "severity", f"Unexpected error: {e}")
            exit(1)
        # Load the CEF severity mappings from a JSON file
        try:
            with open('config/cef_severity.json') as cef_severity:
                cef = json.load(cef_severity)
        except FileNotFoundError as e:
            Core().logger("critical", "Map", "severity", f"CEF severity mapping file not found: {e}")
            exit(1)
        except json.JSONDecodeError as e:
            Core().logger("critical", "Map", "severity", f"Error decoding CEF severity mapping file: {e}")
            exit(1)
        except Exception as e:
            Core().logger("critical", "Map", "severity", f"Unexpected error: {e}")
            exit(1)

        # Map the severity level to its corresponding string representation
        if type == "syslog":
            return syslog.get(str(severity), "unknown")
        elif type == "cef":
            return cef.get(str(severity), "unknown")
        else:
            return "unknown"
        
    def facility(self, facility: int) -> str:
        """
        Converts a numeric syslog facility code into a descriptive name.

        This method reads the mapping data from the 'config/facilities.json' file
        to translate the facility code into a human-readable format. If the facility
        code is not found in the mapping, it returns "unknown".

        Args:
            facility (int): The numeric syslog facility code, representing the source
                    of the log message (e.g., kernel, user-level, mail system).

        Returns:
            str: The descriptive name of the facility, or "unknown" if the code is not
             found in the mapping file.
        """
        # Load the facility mappings from a JSON file
        try:
            with open('config/facilities.json') as facilities_config:
                facilities = json.load(facilities_config)
        except FileNotFoundError as e:
            Core().logger("critical", "Map", "facility", f"Facility mapping file not found: {e}")
            exit(1)
        except json.JSONDecodeError as e:
            Core().logger("critical", "Map", "facility", f"Error decoding facility mapping file: {e}")
            exit(1)
        except Exception as e:
            Core().logger("critical", "Map", "facility", f"Unexpected error: {e}")
            exit(1)
        
        return facilities.get(str(facility), "unknown")

    def protocol(self, protocol: int) -> str:
        """
        Maps a numeric IP protocol number to its corresponding human-readable name.

        This method reads the mapping data from the 'config/ip_protocols.json' file
        to translate the protocol number into a descriptive name. If the protocol
        number is not found in the mapping, it returns the original protocol number.

        Args:
            protocol (int): The numeric IP protocol number to map.

        Returns:
            str: The descriptive name of the protocol, or the original protocol number
             if no mapping is found.
        """
        # Load the protocol mappings from a JSON file
        try:
            with open('config/ip_protocols.json') as ip_protocols:
                protocols = json.load(ip_protocols)
        except FileNotFoundError as e:
            Core().logger("critical", "Map", "protocol", f"Protocol mapping file not found: {e}")
            exit(1)
        except json.JSONDecodeError as e:
            Core().logger("critical", "Map", "protocol", f"Error decoding protocol mapping file: {e}")
            exit(1)
        except Exception as e:
            Core().logger("critical", "Map", "protocol", f"Unexpected error: {e}")
            exit(1)
        
        return protocols.get(str(protocol), protocol)
    
    def cef(self, field: int) -> str:
        """
        Maps a numeric CEF (Common Event Format) extension field index to its descriptive name.

        This method reads the mapping data from the 'config/cef_fields.json' file to translate
        the provided field index into a human-readable name. If the field index is not found
        in the mapping, it returns "unknown".

        Args:
            field (int): The numeric index of the CEF extension field to map.

        Returns:
            str: The descriptive name of the CEF field, or "unknown" if the index is not found
             in the mapping file.
        """
        # Load the CEF field mappings from a JSON file
        try:
            with open('config/cef_fields.json') as cef_fields:
                fields = json.load(cef_fields)
        except FileNotFoundError as e:
            Core().logger("critical", "Map", "cef", f"CEF field mapping file not found: {e}")
            exit(1)
        except json.JSONDecodeError as e:
            Core().logger("critical", "Map", "cef", f"Error decoding CEF field mapping file: {e}")
            exit(1)
        except Exception as e:
            Core().logger("critical", "Map", "cef", f"Unexpected error: {e}")
            exit(1)
        
        return fields.get(str(field), "unknown")
    
    def ip(self, ip: str) -> str:
        """
        Resolve an IP address to a hostname via reverse DNS lookup.

        This method attempts to resolve the given IP address to its corresponding
        hostname using reverse DNS lookup. If the resolution is successful, the
        hostname is returned. If the resolution fails or an error occurs, the
        original IP address is returned instead.

        Args:
            ip (str): The IP address to resolve.

        Returns:
            str: The resolved hostname if successful, or the original IP address
            if the resolution fails or an error occurs.
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.herror:
            return ip
        except Exception as e:
            Core().logger("error", "Map", "ip", f"Error resolving IP '{ip}': {e}")
            return ip
        
    def flow(self, flow: str) -> str:
        """
        Maps a flow type identifier to a descriptive name.

        This method reads the mapping data from the 'config/flow_fields.json' file
        to translate the provided flow identifier into a human-readable name. If the
        flow identifier is not found in the mapping, it returns the original flow string.

        Args:
            flow (str): The flow type identifier to be translated.

        Returns:
            str: The descriptive name of the flow type if found, or the original flow
            string if no mapping exists in the configuration file.
        """
        # Load the flow mappings from a JSON file
        try:
            with open('config/flow_fields.json') as flow_fields:
                flows = json.load(flow_fields)
        except FileNotFoundError as e:
            Core().logger("critical", "Map", "flow", f"Flow mapping file not found: {e}")
            exit(1)
        except json.JSONDecodeError as e:
            Core().logger("critical", "Map", "flow", f"Error decoding flow mapping file: {e}")
            exit(1)
        except Exception as e:
            Core().logger("critical", "Map", "flow", f"Unexpected error: {e}")
            exit(1)

        return flows.get(flow, flow)

    def portforward(self, rule: str) -> str:
        """
        Converts a port-forwarding rule string into a human-readable description.

        This method attempts to match the provided rule string against the keys
        in the 'config/portforward_rules.json' file. If a match is found, it
        returns the corresponding descriptive name. If no match is found, it
        defaults to returning "unknown".

        Args:
            rule (str): The raw port forwarding rule string to be translated.

        Returns:
            str: A human-readable description of the port forwarding rule, or
             "unknown" if no matching entry exists in the configuration file.
        """
        # Load the port forwarding mappings from a JSON file
        try:
            with open('config/portforward_rules.json') as portforward_rules:
                rules = json.load(portforward_rules)
        except FileNotFoundError as e:
            Core().logger("critical", "Map", "portforward", f"Port forwarding rule mapping file not found: {e}")
            exit(1)
        except json.JSONDecodeError as e:
            Core().logger("critical", "Map", "portforward", f"Error decoding port forwarding rule mapping file: {e}")
            exit(1)
        except Exception as e:
            Core().logger("critical", "Map", "portforward", f"Unexpected error: {e}")
            exit(1)
        
        for key, value in rules.items():
            if key in rule:
                return value

        return "unknown"

class LokiExporter:
    """
    LokiExporter facilitates sending log records to a Loki instance.

    This class provides methods to construct the required JSON payload, 
    verify connectivity to the configured Loki endpoint, and export logs 
    with optional retry mechanisms and DNS caching.

    Attributes:
        _name (str): Name of the exporter.
        _version (str): Version of the exporter.
        _description (str): Description of the exporter.
        _author (str): Author of the exporter.
        _email (str): Author's email address.
        url (str): Loki push API base URL (e.g., http://host:3100).
        hostname (str): Extracted hostname from the Loki URL.
        port (int): Extracted port from the Loki URL, if specified.
        prefix (str): Protocol prefix (http or https) extracted from the Loki URL.

    Methods:
        payload(record: dict, labels: dict) -> dict:
            Constructs a Loki-compatible JSON payload from a log record and labels.
        connection(cached_ip: str) -> bool:
            Checks connectivity to the Loki endpoint using the cached IP address.
        cache_dns() -> str:
            Resolves and caches the IP address of the Loki hostname.
        export(record: dict, labels: dict, timestamp: str, cached_ip: str, retry: bool = False) -> tuple:
            Sends the log record to Loki, attaching a timestamp and retrying if necessary.
    """
    def __init__(self):
        """
        Initializes the LokiExporter.

        This constructor sets up the LokiExporter by:
        - Reading the Loki URL from the `LOKI_URL` environment variable (default: "http://localhost:3100").
        - Extracting and storing the hostname, port, and protocol prefix from the URL.
        - Setting metadata attributes such as:
          - `_name`: The name of the exporter.
          - `_version`: The version of the exporter.
          - `_description`: A brief description of the exporter.
          - `_author`: The author's name.
          - `_email`: The author's email address.
        """
        self._name = "LokiExporter"
        self._version = "1.0.0"
        self._description = "Loki exporter for the application."
        self._author = "Rogly"
        self._email = "rogly@rogly.net"
        self.url = os.getenv("LOKI_URL", "http://localhost:3100")
        self.hostname = re.match(r"http[s]?://([^:/]+)", self.url).group(1)
        self.port = int(re.search(r":(\d+)", self.url).group(1)) if ":" in self.url else None
        self.prefix = re.match(r"(http[s]?)://", self.url).group(1) if self.url else None
    
    def payload(self, record: dict, labels: dict) -> dict:
        """
        Constructs a Loki push API payload.

        This method combines the provided log record and labels into the
        JSON structure required by Loki's /loki/api/v1/push endpoint. It
        includes a nanosecond-precision timestamp and adds a default label
        "job" with the value "unifi-exporter".

        Args:
            record (dict): The log record to send, which will be serialized to JSON.
            labels (dict): A dictionary of stream labels with string keys and values.

        Returns:
            dict: A dictionary containing the Loki payload with the following structure:
            - "streams": A list of streams, each containing:
                - "stream": The labels dictionary.
                - "values": A list of [timestamp, record] entries.
        """
        labels["job"] = "unifi-exporter"
        payload = {
            "streams": [
                {
                    "stream": labels,
                    "values": [
                        [str(int(datetime.datetime.now(tz=pytz.timezone(os.getenv("TZ", "UTC"))).timestamp() * 1e9)), json.dumps(record)]
                    ]
                }
            ]
        }
        return payload
    
    def connection(self, cached_ip: str) -> bool:
        """
        Check connectivity to the configured Loki endpoint.

        This method performs an HTTP GET request to the Loki endpoint using the cached IP address
        and validates the response. It ensures the endpoint is reachable and functioning correctly.

        Logs detailed errors for:
          - Non-200 HTTP response codes.
          - Unreachable endpoint or connection issues.

        Args:
            cached_ip (str): The cached IP address of the Loki hostname.

        Returns:
            bool: True if the endpoint is reachable and returns HTTP 200, False otherwise.
        """
        # Check if the URL is reachable
        response = requests.get(f"{self.prefix}://{cached_ip}:{self.port}")
        if response.status_code != 200:
            Core().logger("error", "loki-exporter", "connection", f"Error connecting to Loki: {response.status_code}")
            cached_ip = None
            return False
        else:
            return True

    def cache_dns(self) -> str:
        """
        Resolves and caches the IP address of the Loki hostname.

        This method performs a DNS lookup for the hostname extracted from the Loki URL
        and returns the resolved IP address. If the resolution fails, it logs an error
        and returns None.

        Returns:
            str: The resolved IP address if successful, or None if the resolution fails.
        """
        try:
            ip = socket.gethostbyname(self.hostname)
            Core().logger("informational", "loki-exporter", "cache_dns", f"Cached IP: {ip}")
            return ip
        except socket.gaierror as e:
            Core().logger("error", "loki-exporter", "cache_dns", f"Error resolving hostname '{self.hostname}': {e}")
            return None
        
    def export(self, record: dict, labels: dict, timestamp: str, cached_ip: str = None, retry: bool = False) -> tuple:
        """
        Exports a log record to Loki.

        This method performs the following steps:
        1. Verifies if the Loki endpoint is reachable using the cached IP address.
        2. Optionally retries DNS resolution and connectivity if the initial attempt fails.
        3. Adds the provided source timestamp to the log record, if specified.
        4. Constructs the Loki-compatible payload using the log record and labels.
        5. Sends the payload to the Loki endpoint via an HTTP POST request.

        If the export fails and retry is enabled, it attempts to resolve the DNS again
        and retries the export process.

        Args:
            record (dict): The log record to export, which will be serialized to JSON.
            labels (dict): A dictionary of stream labels with string keys and values.
            timestamp (str): Optional original timestamp to attach as "source_timestamp".
            cached_ip (str): The cached IP address of the Loki hostname.
            retry (bool, optional): Whether to retry the export process on failure. Defaults to False.

        Returns:
            tuple: A tuple containing:
            - cached_ip (str): The cached IP address used for the export.
            - success (bool): True if the export succeeded, False otherwise.
        """
        if retry == True:
            cached_ip = self.cache_dns()
            if not cached_ip:
                Core().logger("error", "loki-exporter", "export", f"Error caching DNS: {cached_ip}")
                return None, False
            
        if timestamp:
            try:
                record["source_timestamp"] = timestamp
            except Exception as e:
                Core().logger("error", "loki-exporter", "export", f"Error archiving timestamp: {e}")
                return cached_ip, False
            
        # Generate the Loki payload
        try:
            payload = self.payload(record, labels)
        except Exception as e:
            Core().logger("error", "loki-exporter", "export", f"Error generating Loki payload: {e}")
            return cached_ip, False
        
        # Send the payload to Loki
        if payload:
            if self.connection(cached_ip):
                try:
                    response = requests.post(f"{self.prefix}://{cached_ip}:{self.port}/loki/api/v1/push", json=payload)
                    if response.status_code != 204:
                        Core().logger("error", "loki-exporter", "export", f"Error exporting log to Loki: {response.status_code}")
                        Core().logger("error", "loki-exporter", "export", f"Payload: {payload}")
                        return cached_ip, False
                    else:
                        return cached_ip, True
                except Exception as e:
                    if retry == False:
                        self.export(record, labels, timestamp, cached_ip, retry=True)
                    else:
                        Core().logger("error", "loki-exporter", "export", f"Error exporting log to Loki: {e}")
                        return cached_ip, False
        else:
            Core().logger("error", "loki-exporter", "export", f"Loki payload is empty, cannot export log. {payload}")
            return cached_ip, False

class GeoIP:
    """
    GeoIP utilities for managing and querying a MaxMind GeoLite2-City database.

    This class provides functionality to:
      - Download and extract the GeoIP database archive from MaxMind.
      - Retrieve and validate the SHA256 hash of the database to ensure integrity.
      - Automatically update the local database when a newer version is available.
      - Filter out IP addresses that are private, loopback, link-local, multicast, or reserved.
      - Perform city-level GeoIP lookups and return structured geographic data in a GeoIPData object.

    Environment variables required for authenticated downloads:
      - GEOIP_ACCOUNT_ID: MaxMind account ID.
      - GEOIP_LICENSE_KEY: MaxMind license key.

    This class ensures that the GeoIP database is always up-to-date and provides robust error handling
    for download, extraction, and lookup operations.
    """
    def __init__(self):
        """
        Initializes the GeoIP utility.

        This constructor sets up the GeoIP utility by:
        - Reading MaxMind account ID and license key from environment variables.
        - Setting metadata attributes such as name, version, description, author, and email.
        - Defining download URLs for the GeoLite2-City database and its hash file.
        - Ensuring the 'database' directory exists, creating it if necessary.
        - Checking for the presence of the GeoLite2-City database file; if missing, it downloads and extracts the database automatically.
        """
        self._name = "GeoIP"
        self._version = "1.0.0"
        self._description = "GeoIP utilities for the application."
        self._author = "Rogly"
        self._email = "rogly@rogly.net"
        self._account_id = os.getenv("GEOIP_ACCOUNT_ID", None)
        self._license_key = os.getenv("GEOIP_LICENSE_KEY", None)
        self._db_url = 'https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz'
        self._hash_url = 'https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz.sha256'
        
        if self._account_id is not None and self._license_key is not None:
            # Check if the database directory exists, if not create it
            if not os.path.exists("database"):
                os.makedirs("database")
            
            # Check if the database file exists, if not create it
            if not os.path.exists("database/geoip.mmdb"):
                Core().logger("informational", "geoip", "init", "GeoIP database not found, downloading it now...")
                self.download()
    
    class GeoIPData:
        """
        Represents the results of a GeoIP lookup.

        This class encapsulates geographic and network-related information
        obtained from a GeoIP database query. It provides structured access
        to various attributes, including location details and traits.

        Attributes:
            full (dict): The complete GeoIP data returned by the MaxMind reader.
            traits (dict): Network traits, such as autonomous system information.
            continent (str): The ISO code of the continent (e.g., 'NA' for North America).
            country (str): The ISO code of the country (e.g., 'US' for the United States).
            subdivision (str): The ISO code of the first-level subdivision (e.g., 'CA' for California).
            city (str): The name of the city.
            postal (str): The postal code of the location.
            latitude (float): The latitude coordinate of the location in decimal degrees.
            longitude (float): The longitude coordinate of the location in decimal degrees.
        """
        def __init__(self, full: dict = None, traits: dict = None, continent: str = None, country: str = None, subdivision: str = None, city: str = None, postal: str = None, latitude: str = None, longitude: str = None):
            """
            Initializes a GeoIPData instance with geographic and network-related information.

            Args:
                full (dict, optional): The complete GeoIP data dictionary returned by the MaxMind reader.
                traits (dict, optional): Network traits, such as autonomous system information.
                continent (str, optional): The ISO code of the continent (e.g., "NA" for North America).
                country (str, optional): The ISO code of the country (e.g., "US" for the United States).
                subdivision (str, optional): The ISO code of the first-level subdivision (e.g., "CA" for California).
                city (str, optional): The name of the city.
                postal (str, optional): The postal code of the location.
                latitude (float, optional): The latitude coordinate of the location in decimal degrees.
                longitude (float, optional): The longitude coordinate of the location in decimal degrees.
            """
            self.full = full
            self.traits = traits
            self.continent = continent
            self.country = country
            self.subdivision = subdivision
            self.city = city
            self.postal = postal
            self.latitude = latitude
            self.longitude = longitude

        def __repr__(self):
            """
            Returns a string representation of the GeoIPData instance.

            This representation includes all the attributes of the instance:
            - `full`: The complete GeoIP data dictionary.
            - `continent`: The ISO code of the continent (e.g., "NA" for North America).
            - `country`: The ISO code of the country (e.g., "US" for the United States).
            - `subdivision`: The ISO code of the first-level subdivision (e.g., "CA" for California).
            - `city`: The name of the city.
            - `postal`: The postal code of the location.
            - `traits`: Network traits, such as autonomous system information.
            - `latitude`: The latitude coordinate of the location in decimal degrees.
            - `longitude`: The longitude coordinate of the location in decimal degrees.

            Returns:
                str: A string representation of the GeoIPData instance.
            """
            return f"GeoIPData(full={self.full}, continent={self.continent}, country={self.country}, subdivision={self.subdivision}, city={self.city}, postal={self.postal}, traits={self.traits}, latitude={self.latitude}, longitude={self.longitude})"
        
    def download(self) -> bool:
        """
        Downloads the GeoIP database and extracts it to the specified location.

        This method retrieves the GeoLite2-City database archive from MaxMind,
        extracts the database file, and saves it to the 'database' directory.
        It also downloads the corresponding SHA256 hash file for integrity checks.

        Returns:
            bool: True if the database and hash file are downloaded and extracted successfully, False otherwise.
        """
        try:
            # Download the GeoIP database
            with requests.get(self._db_url, auth=(self._account_id, self._license_key), stream=True) as response:
                if response.status_code == 200:
                    with open("database/geoip.tar.gz", "wb") as file:
                        for chunk in response.iter_content(chunk_size=8192):
                            file.write(chunk)

                    with tarfile.open("database/geoip.tar.gz", "r:gz") as tar:
                        for member in tar.getmembers():
                            if member.name.endswith(".mmdb"):
                                member.name = "geoip.mmdb"
                                tar.extract(member, path="./database")
                                break

                    os.remove("database/geoip.tar.gz")
                    Core().logger("informational", "geoip", "download", "GeoIP database downloaded and extracted successfully.")
                else:
                    Core().logger("error", "geoip", "download", f"Error downloading GeoIP database: {response.status_code}")
                    exit(1)

            # Download the hash file
            with requests.get(self._hash_url, auth=(self._account_id, self._license_key), stream=True) as response:
                    if response.status_code == 200:
                        with open("database/geoip.sha256", "wb") as file:
                            for chunk in response.iter_content(chunk_size=8192):
                                file.write(chunk)
                        Core().logger("informational", "geoip", "download", "GeoIP hash downloaded successfully.")
                    else:
                        Core().logger("error", "geoip", "download", f"Error downloading GeoIP hash: {response.status_code}")
                        exit(1)
            return True
        
        except Exception as e:
            Core().logger("error", "geoip", "download", f"Error downloading GeoIP database: {e}")
            exit(1)

    def hash(self) -> str:
        """
        Retrieves the GeoIP hash value from the MaxMind server.

        This method downloads the SHA256 hash file for the GeoLite2-City database
        from the MaxMind server. The hash is used to verify the integrity of the
        database and check for updates.

        Returns:
            str: The hash value as a string if the download is successful, or None
             if an error occurs during the process.
        """
        try:
            with requests.get(self._hash_url, auth=(self._account_id, self._license_key), stream=True) as response:
                    if response.status_code == 200:
                        hash = response.content.decode('utf-8').strip()
                    else:
                        Core().logger("error", "geoip", "hash", f"Error downloading GeoIP hash: {response.status_code}")
                        return None
            return hash
        except Exception as e:
            Core().logger("error", "geoip", "hash", f"Error downloading GeoIP hash: {e}")
            return None

    def update(self):
        """
        Ensures the GeoIP database is installed and up to date.

        This method checks if the GeoIP database and its associated hash file are present.
        If the database is missing, it downloads and installs the latest version.
        If the database is present, it compares the local hash with the remote hash
        to determine if an update is needed. If the hashes differ, the latest version
        of the database is downloaded and installed.

        Returns:
            bool: True if the database is up to date or successfully updated, False otherwise.
        """
        # Check if the hash file exists
        if not os.path.exists("database/geoip.sha256"):
            Core().logger("informational", "geoip", "update", "GeoIP database is not installed, installing it now...")
            # Download the hash and replace the existing database
            return self.download()
        
        # Check if the database is up to date
        else:
            # Read the hash value from the file
            with open("database/geoip.sha256", "r") as file:
                hash_value = file.read().strip()
                Core().logger("informational", "geoip", "update", f"Current hash value: {hash_value}")
            
            # Get the hash value from the server
            remote_hash_value = self.hash()
            Core().logger("informational", "geoip", "update", f"Remote hash value: {remote_hash_value}")


            # Compare the hash value with the existing database
            if hash_value != remote_hash_value:
                Core().logger("informational", "geoip", "update", "GeoIP database is outdated. Downloading the latest version...")
                # Download the latest version of the database
                return self.download()
            else:
                Core().logger("informational", "geoip", "update", "GeoIP database is up to date.")
                return True

    def filter(self, ip: str) -> bool:
        """
        Filters the given IP address to determine its suitability for GeoIP lookup.

        This method checks if the IP address is public and not part of any reserved ranges,
        such as private, loopback, link-local, multicast, or other reserved addresses.
        Only public IP addresses are valid for GeoIP lookups.

        Args:
            ip (str): The IP address to validate.

        Returns:
            bool: True if the IP address is valid for GeoIP lookup (public), False otherwise.
        """
        try:
            # Check if the IP is a valid IPv4 or IPv6 address
            ip = ipaddress.ip_address(ip)
        except ValueError:
            Core().logger("error", "geoip", "filter", f"Invalid IP address: {ip}")
            return False

        # Check for IPv4-specific reserved ranges
        if isinstance(ip, ipaddress.IPv4Address):
            if ip.is_private:
                Core
                return False
            if ip.is_loopback:

                return False
            if ip.is_link_local:

                return False
            if ip.is_multicast:

                return False
            if ip.is_reserved:

                return False

        # Check for IPv6-specific reserved ranges
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.is_private:
                Core().logger("debug", "geoip", "filter", f"This is a Private IP Address {ip}")
                return False
            if ip.is_loopback:
                Core().logger("debug", "geoip", "filter", f"This is a Loopback IP Address: {ip}")
                return False
            if ip.is_link_local:
                Core().logger("debug", "geoip", "filter", f"This is a Link Local IP Address: {ip}")
                return False
            if ip.is_multicast:
                Core().logger("debug", "geoip", "filter", f"This is a Multicast IP Address: {ip}")
                return False
            if ip.is_reserved:
                Core().logger("debug", "geoip", "filter", f"This is a Reserved IP Address: {ip}")
                return False

        # If none of the above conditions are met, the IP is valid for GeoIP lookup
        return True

    def lookup(self, ip: str) -> GeoIPData:
        """
        Performs a city-level GeoIP lookup for the given IP address.

        This method validates the IP address to ensure it is suitable for a public GeoIP lookup
        (e.g., not private, loopback, or reserved). It also ensures the GeoIP database is present
        and up to date. If the database is missing, it will be downloaded automatically.

        The method queries the MaxMind GeoLite2-City database to retrieve geographic information
        about the provided IP address. The resulting data is structured into a GeoIPData object,
        which includes details such as continent, country, subdivision, city, postal code,
        latitude, longitude, network traits, and the full record.

        Args:
            ip (str): The IP address to look up.

        Returns:
            GeoIPData: A GeoIPData object containing structured geographic and network-related
                   information, or None if the lookup fails or the IP is not valid for lookup.
        """
        # Check if the the IP address is valid for GeoIP lookup
        if not self.filter(ip):
            Core().logger("debug", "geoip", "lookup", f"IP address {ip} is not valid for GeoIP lookup.")
            return None
        
        # Check if the database is installed
        if not os.path.exists("database/geoip.mmdb"):
            # Download the database if it doesn't exist
            self.update()
        
        # Open the GeoIP database
        try:
            with geoip2.database.Reader("database/geoip.mmdb") as database:
                # Perform the lookup
                client = database.city(ip)
                data = client.to_dict()

                # Extract only english names from the data
                for key, value in data.items():
                    try:
                        if isinstance(value, list):
                            for sub_item in value:
                                if isinstance(sub_item, dict):
                                    try:
                                        sub_item['name'] = sub_item['names']['en']
                                        del sub_item['names']
                                    except KeyError:
                                        continue
                        else:
                            try:
                                data[key]["name"] = data[key]['names']['en']
                                del data[key]['names']
                            except KeyError:
                                continue
                    except Exception as e:
                        Core().logger("error", "geoip", "lookup", f"Error extracting names from GeoIP data: {e}")
                        continue
        except Exception as e:
            Core().logger("error", "geoip", "lookup", f"Error opening GeoIP database: {e}")
            return None
        
        # store the data in a GeoIPData object
        result = self.GeoIPData(
            full = data,
            traits = data.get("traits", None),
            continent = data.get("continent", {}).get("code", None),
            country = data.get("country", {}).get("iso_code", None),
            subdivision = data.get("subdivision", [{}])[0].get("iso_code", "none") if data.get("subdivision") else None,
            city = data.get("city", {}).get("name", None),
            postal = data.get("postal", {}).get("code", None),
            latitude = data.get("location", {}).get("latitude", None),
            longitude = data.get("location", {}).get("longitude", None),
        )

        return result
