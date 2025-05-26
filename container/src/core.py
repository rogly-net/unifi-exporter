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
    This class provides core utilities such as logging, environment variable checks,
    signal handling, and data extraction.
    It also includes helper methods for managing application state and handling errors.
    """
    def __init__(self):
        """
        Initializes the Core class with default attributes.
        Sets up metadata such as name, version, description, author, and email.
        Also initializes a stop flag for application control.
        """
        self._name = "CoreUtilities"
        self._version = "1.0.0"
        self._description = "Core utilities for the application."
        self._author = "Rogly"
        self._email = "rogly@rogly.net"
        self.stop_flag = False

    class Extracted:
        """
        Class to represent extracted data from a message.
        This class encapsulates the extracted value, the original message, 
        and the cleaned message after extraction.
        """
        def __init__(self, value: str = None, original: str = None, cleaned: str = None):
            """
            Initializes the Extracted class.

            Args:
                value (str, optional): The extracted value. Defaults to None.
                original (str, optional): The original message from which the value was extracted. Defaults to None.
                cleaned (str, optional): The cleaned message after extraction. Defaults to None.
            """
            self.value = value
            self.original = original
            self.cleaned = cleaned
        def __str__(self):
            """
            Returns:
                str: A string representation of the Extracted object, including the extracted value,
                the original message, and the cleaned message.
            """
            return f"Extracted(value={self.value}, original={self.original}, cleaned={self.cleaned})"

    def logger(self, level: str, program: str, function: str, message: str) -> None:
        """
        Logs a message with the specified level, program, function, and message.

        Args:
            level (str): The log level (e.g., "informational", "ERROR").
            program (str): The name of the program.
            function (str): The name of the function.
            message (str): The log message.

        Returns:
            None
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
        Checks if the required environment variables are set in the operating system's environment.

        Args:
            env_vars (list): A list of strings representing the names of the required environment variables.

        Returns:
            bool: Returns True if all required environment variables are set.
        """
        for var in env_vars:
            if var not in os.environ:
                self.logger("critical", "core", "checl_environment", f"Environment variable {var} is not set.")
                exit(1)
        
        return True
    
    def sigterm(self, signum: int, frame: FrameType) -> None:
        """
        Handles the SIGTERM signal to gracefully shut down the application.

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

        Args:
            message (str): The input text to search.
            regex (str): The regular expression pattern to match.
            group (int, optional): The capture group index to extract. Defaults to 0.

        Returns:
            Optional[Core.Extracted]: An Extracted object containing:
            - value (str): The matched substring.
            - original (str): The original message.
            - cleaned (str): The message with the matched text removed.
            None if no match is found.
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
    Map utilities for converting numeric and coded values into human-readable formats.

    Provides methods to:
        - priority(priority: str) -> Priority
            Map a syslog priority number to its facility and severity components.
        - severity(type: str, severity: int) -> str
            Map a syslog or CEF severity level to its textual description.
        - facility(facility: int) -> str
            Map a syslog facility code to its name.
        - protocol(protocol: int) -> str
            Map an IP protocol number to its protocol name.
        - cef(field: int) -> str
            Map a CEF field index to the corresponding syslog field name.
        - ip(ip: str) -> str
            Resolve an IP address to its hostname, or return the IP if resolution fails.
        - flow(flow: str) -> str
            Map a flow type identifier to its descriptive name.
        - portforward(rule: str) -> str
            Map a port forwarding rule string to a human-readable rule name.

    Each method reads from its respective JSON configuration file under `config/`
    and returns the mapped value or "unknown" if no match is found.
    """
    def __init__(self):
        """
        Initializes the Map class.
        Loads mapping configurations from JSON files in the 'config' directory and
        prepares them for value-to-string translation.

        JSON files included:
          - syslog_severity.json
          - cef_severity.json
          - facilities.json
          - ip_protocols.json
          - cef_fields.json
          - flow_fields.json
          - portforward_rules.json
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

        Attributes:
            facility (int): The syslog facility code (0-23).
            severity (int): The syslog severity level (0-7).
        """
        def __init__(self, facility: int, severity: int):
            """
            Initialize a Priority object representing a syslog priority.

            Args:
                facility (int): The syslog facility code (0–23).
                severity (int): The syslog severity level (0–7).
            """
            self.facility = facility
            self.severity = severity

        def __repr__(self):
            """
            Return the canonical string representation of this Priority instance.
            """
            return f"Priority(facility={self.facility}, severity={self.severity})"

    def priority(self, priority: str) -> Priority:
        """
        Converts a syslog priority value to its facility and severity components.

        Args:
            priority (str): The numeric syslog priority (as a string or integer).

        Returns:
            Priority: An object with `facility` and `severity` attributes.
        """
        facility = int(priority) // 8
        severity = int(priority) % 8
        return self.Priority(facility, severity)

    def severity(self, type: str, severity: int) -> str:
        """
        Translate a numeric severity code to its human-readable label.

        Loads mapping data from JSON files in the 'config' directory:
          - 'config/syslog_severity.json' for syslog severity codes
          - 'config/cef_severity.json' for CEF severity levels

        Args:
            type (str): The mapping type, either "syslog" or "cef".
            severity (int): The numeric severity value to translate.

        Returns:
            str: The corresponding severity description, or "unknown" if the value
             or mapping type is not found.
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
        Translate a numeric syslog facility code to its human-readable name.

        Loads mapping data from 'config/facilities.json'.

        Args:
            facility (int): The numeric syslog facility code.

        Returns:
            str: The corresponding facility name, or "unknown" if not found.
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
        Translate a numeric IP protocol number to its human-readable name.

        Loads mapping data from 'config/ip_protocols.json'.

        Args:
            protocol (int): The numeric IP protocol number.

        Returns:
            str: The corresponding protocol name, or "unknown" if not found.
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
        Translate a numeric CEF extension field index to its human-readable name.

        Loads mapping data from 'config/cef_fields.json'.

        Args:
            field (int): The numeric CEF extension field index.

        Returns:
            str: The corresponding field name, or "unknown" if not found.
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

        Attempts to perform a reverse DNS lookup on the given IP. If the lookup
        succeeds, returns the corresponding hostname; otherwise, returns the
        original IP address.

        Args:
            ip (str): The IP address to resolve.

        Returns:
            str: The resolved hostname on success, or the input IP string if
             resolution fails.
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
        Translate a flow identifier to its descriptive name.

        Loads mapping data from 'config/flow_fields.json'. If the flow code exists
        in the configuration, returns its human-readable description. Otherwise,
        returns the original flow string.

        Args:
            flow (str): The flow type identifier to map.

        Returns:
            str: The mapped flow name, or the original flow string if no mapping is found.
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
        Translate a port-forwarding rule string into a human-readable name.

        Attempts to match the given rule text against entries in
        'config/portforward_rules.json'. Returns the mapped description
        if a matching key is found, otherwise returns "unknown".

        Args:
            rule (str): The raw port forwarding rule identifier or text.

        Returns:
            str: The corresponding human-readable rule name, or "unknown" if no mapping exists.
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
    LokiExporter handles sending log records to a Loki instance.

    This class constructs the necessary JSON payload, verifies connectivity
    to the configured Loki endpoint, and posts logs.

    Attributes:
        _name (str): Exporter name.
        _version (str): Exporter version.
        _description (str): Exporter description.
        _author (str): Author name.
        _email (str): Author email.
        url (str): Loki push API URL (e.g., http://host:3100/loki/api/v1/push).

    Methods:
        payload(record: dict, labels: dict) -> dict:
            Build a Loki-compatible JSON payload from a log record and labels.
        connection() -> bool:
            Check if the Loki endpoint is reachable and returns HTTP 200.
        export(record: dict, labels: dict, timestamp: str) -> bool:
            Send the log record to Loki, attaching a timestamp; returns True on success.
    """
    def __init__(self):
        """
        Initializes the LokiExporter.

        Reads the Loki URL from the LOKI_URL environment variable
        (default: "http://localhost:3100/loki/api/v1/push") and sets the
        following metadata attributes:
          - _name
          - _version
          - _description
          - _author
          - _email
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
        Build a Loki push API payload.

        This method merges the given log record and labels into the
        JSON structure required by Loki’s /loki/api/v1/push endpoint.
        It attaches a nanosecond‐precision timestamp and includes the
        "job": "unifi-syslog-test" label by default.

        Args:
            record (dict): A log record to send (will be JSON‐serialized).
            labels (dict): A dict of stream labels (string keys/values).

        Returns:
            dict: A payload dict with a "streams" list, each containing:
              - "stream": the labels
              - "values": a list of [timestamp, record] entries
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

        Performs an HTTP GET against `self.url` and validates:
          - URL format (must start with http:// or https:// and include a hostname, optional port)
          - HTTP response code is 200

        Logs detailed errors for:
          - Invalid URL format
          - Non-200 responses
          - Unreachable endpoint

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
        Cache the DNS resolution of a given URL.

        This method resolves the hostname of the provided URL and returns
        the IP address. It also caches the result to avoid repeated lookups.

        Args:
            url (str): The URL to resolve.

        Returns:
            str: The resolved IP address.
        """
        try:
            ip = socket.gethostbyname(self.hostname)
            Core().logger("informational", "loki-exporter", "cache_dns", f"Cached IP: {ip}")
            return ip
        except socket.gaierror as e:
            Core().logger("error", "loki-exporter", "cache_dns", f"Error resolving hostname '{self.hostname}': {e}")
            return None
        
    def export(self, record: dict, labels: dict, timestamp: str, cached_ip: str, retry: bool = False) -> tuple:
        """
        Export a log record to Loki.

        This method verifies the Loki endpoint is reachable, adds the optional
        source timestamp to the record, constructs the Loki payload, and sends
        it via HTTP POST.

        Args:
            record (dict): The log record to export.
            labels (dict): A dict of stream labels for the log entry.
            timestamp (str): Optional original timestamp to attach as "source_timestamp".

        Returns:
            bool: True if the export succeeded, False otherwise.
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

    This class handles:
      - Downloading and extracting the GeoIP database archive.
      - Retrieving and validating the SHA256 hash of the database.
      - Updating the local database when the remote checksum changes.
      - Filtering out private, loopback, link-local, multicast, and reserved IPs.
      - Performing city-level lookups and returning structured GeoIPData.

    Environment variables:
      - GEOIP_ACCOUNT_ID: MaxMind account ID for authenticated downloads.
      - GEOIP_LICENSE_KEY: MaxMind license key for authenticated downloads.
    """
    def __init__(self):
        """
        Initializes the GeoIP utility.

        Reads MaxMind account ID and license key from environment variables,
        sets metadata (name, version, description, author, email) and download URLs.
        Ensures the 'database' directory exists and that the GeoLite2-City database file
        is present; if not, downloads and extracts it automatically.
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
        
        # Check if the database directory exists, if not create it
        if not os.path.exists("database"):
            os.makedirs("database")
        
        # Check if the database file exists, if not create it
        if not os.path.exists("database/geoip.mmdb"):
            Core().logger("informational", "geoip", "init", "GeoIP database not found, downloading it now...")
            self.download()
    
    class GeoIPData:
        """
        Class to represent GeoIP lookup results.

        Attributes:
            full (dict): Complete GeoIP data returned by the MaxMind reader.
            traits (dict): Traits section of the GeoIP data (e.g., autonomous system info).
            continent (str): Continent ISO code (e.g., 'NA').
            country (str): Country ISO code (e.g., 'US').
            subdivision (str): First subdivision (state/province) ISO code (e.g., 'CA').
            city (str): City name.
            postal (str): Postal code.
            latitude (float): Geographic latitude.
            longitude (float): Geographic longitude.
        """
        def __init__(self, full: dict = None, traits: dict = None, continent: str = None, country: str = None, subdivision: str = None, city: str = None, postal: str = None, latitude: str = None, longitude: str = None):
            """
            Initialize a GeoIPData instance with selected geographic information.

            Args:
                full (dict): Complete GeoIP data dictionary returned by the MaxMind reader.
                traits (dict): Traits section from the GeoIP data (e.g., autonomous system info).
                continent (str): Continent ISO code (e.g., "NA").
                country (str): Country ISO code (e.g., "US").
                subdivision (str): First subdivision ISO code (state or province, e.g., "CA").
                city (str): City name.
                postal (str): Postal code.
                latitude (float): Latitude coordinate in decimal degrees.
                longitude (float): Longitude coordinate in decimal degrees.
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
            Return the canonical string representation of this GeoIPData instance,
            including all its attributes: full record, continent code, country code,
            subdivision code, city, postal code, traits, latitude, and longitude.
            """
            return f"GeoIPData(full={self.full}, continent={self.continent}, country={self.country}, subdivision={self.subdivision}, city={self.city}, postal={self.postal}, traits={self.traits}, latitude={self.latitude}, longitude={self.longitude})"
        
    def download(self) -> bool:
        """
        Downloads the GeoIP database and extracts it to the specified location.
        Returns:
            bool: True if the database is downloaded and extracted successfully.
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
        Downloads the GeoIP hash file.
        Returns:
            str: The hash value as a string.
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
        Checks if the GeoIP database is installed and up to date.
        If not, downloads the latest version of the database.
        
        Returns:
            bool: True if the database is up to date, False otherwise.
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
        Determines if the given IP address should be included in a GeoIP lookup.
        
        This method filters out IP addresses that are private, loopback, link-local,
        multicast, or reserved, as these are not suitable for public GeoIP lookups.

        Args:
            ip (str): The IP address to check.

        Returns:
            bool: True if the IP is valid for GeoIP lookup (i.e., public), False otherwise.
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

        This method checks if the IP is suitable for public GeoIP lookup (not private, loopback, etc.),
        ensures the GeoIP database is present and up to date, and then queries the MaxMind GeoLite2-City
        database for geographic information about the IP.

        Args:
            ip (str): The IP address to look up.

        Returns:
            GeoIPData: An object containing structured geographic data (continent, country, subdivision,
                   city, postal code, latitude, longitude, traits, and the full record), or None if
                   the lookup fails or the IP is not valid for lookup.
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
