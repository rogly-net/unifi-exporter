import src.core as core
import re

class Syslog:
    """
    Syslog message parser and handler.

    This class provides methods to parse, map, and enrich syslog messages,
    including generic and flow log types. It extracts relevant fields,
    applies mappings, enriches with geo and DNS data, and prepares records
    and labels for export.
    """

    def __init__(self):
        """
        Initializes the Syslog class and its core components.

        Sets up core utilities, mapping, exporter, geo lookup, and initializes
        empty record and label dictionaries for parsing syslog messages.
        """
        self.core = core.Core()
        self.map = core.Map()
        self.loki = core.LokiExporter()
        self.geo = core.GeoIP()
        self.record = {}
        self.labels = {}
    
    class Log:
        """
        Represents a parsed Syslog log entry.

        Stores the extracted record fields and labels for a single Syslog message.
        Used as a container for parsed data to be exported or further processed.
        """
        def __init__(self, record: dict, labels: dict):
            """
            Initializes the Log class with parsed record and label data.

            Args:
                record (dict): The parsed fields from the Syslog message.
                labels (dict): The labels associated with the parsed fields.
            """
            self.record = record
            self.labels = labels

    def generic(self, message: str) -> Log:
        """
        Parses a generic Syslog message.

        Args:
            message (str): The Syslog message to parse.

        Returns:
            Log: An instance of the Log class containing the parsed record and labels,
             or None if parsing fails.
        """
        self.core.logger("debug", "syslog", "generic", f"Parsing generic syslog message: {message}")
        
        # Set source and type labels
        self.labels["source"] = "syslog"
        self.labels["type"] = "generic"

        # Check the next field in the message
        next_field = self.core.extract(message, r"(^\S+)", 1)
        self.core.logger("debug", "syslog", "generic", f"Extracted next field: {next_field.value if next_field else 'None'}")
        
        if next_field:
            # Extract service from remaining message
            service = self.core.extract(next_field.cleaned, r"^:?\s?(\S+\S+)", 1)
            self.core.logger("debug", "syslog", "generic", f"Extracted service: {service.value if service else 'None'}")
            
            if service:
                # Extract Service Name from Service Value
                service_name = self.core.extract(service.value, r"(^\S+)\b(?:\[\d*\])?:", 1)
                self.core.logger("debug", "syslog", "generic", f"Extracted service name: {service_name.value if service_name else 'None'}")
                
                if service_name:
                    # Assign service_name label
                    self.labels["service_name"] = service_name.value
                    self.core.logger("debug", "syslog", "generic", f"Assigned service_name label: {self.labels['service_name']}")
                    
                    # Extract service id from service value
                    service_id = self.core.extract(service.value, r"^\S+\[(\d+)\]\S+", 1)
                    self.core.logger("debug", "syslog", "generic", f"Extracted service ID: {service_id.value if service_id else 'None'}")
                    
                    if service_id:
                        # Assign service id record
                        self.record["service_id"] = service_id.value
                        self.record["message"] = service.cleaned
                        self.core.logger("debug", "syslog", "generic", f"Assigned record: {self.record}")
                        return self.Log(self.record, self.labels)
                    else:
                        self.record["message"] = service.cleaned
                        self.core.logger("debug", "syslog", "generic", f"Assigned record without service ID: {self.record}")
                        return self.Log(self.record, self.labels)
                else:
                    self.core.logger("error", "syslog", "generic", f"Service Name not found in Service: {service.value}")
                    return
            else:
                self.core.logger("error", "syslog", "generic", f"Service not found in message: {next_field.cleaned}")
                return
        else:
            self.core.logger("error", "syslog", "generic", f"Next field not found in message: {message}")
            return

    def flow(self, message: str) -> Log:
        """
        Parses a Syslog flow log message, extracting and enriching flow-specific fields.

        This method determines if the message is a portforward or general flow log,
        parses relevant fields, enriches with geo and DNS data, and returns a Log object.

        Args:
            message (str): The Syslog message to parse.

        Returns:
            Log: An instance of the Log class containing the parsed record and labels,
            or None if parsing fails.
        """

        # Set source and type labels
        self.labels["source"] = "syslog"
        self.labels["service_name"] = "firewall"

        def common(message: str) -> Syslog.Log:
            """
            Parses and enriches common flow log fields from a Syslog message.

            This function extracts TCP flags, key-value pairs, and enriches
            IP addresses with geo and DNS data. It also assigns label fields
            and handles MAC address splitting for source and destination.

            Args:
                message (str): The Syslog message to parse.

            Returns:
                Syslog.Log: Parsed log object with record and label data, or None if parsing fails.
            """
            # Create an empty list for TCP Flags
            tcp = []

            # Load the flow label fields from the file
            try:
                with open("config/flow_label_fields.list", "r") as label_fields_list:
                    label_fields = label_fields_list.read().splitlines()
            except FileNotFoundError as e:
                self.core.logger("critical", "syslog", "flow", f"Label fields file not found: {e}")
                exit(1)
            except Exception as e:
                self.core.logger("critical", "syslog", "flow", f"Error loading label fields: {e}")
                exit(1)
            
            # Load the TCP Flags from the file
            try:
                with open("config/tcp_flags.list", "r") as tcp_flags_list:
                    tcp_flags = tcp_flags_list.read().splitlines()
            except FileNotFoundError as e:
                self.core.logger("critical", "syslog", "flow", f"TCP Flags file not found: {e}")
                exit(1)
            except Exception as e:
                self.core.logger("critical", "syslog", "flow", f"Error loading TCP Flags: {e}")
                exit(1)

            # Extract all Flags
            try:
                flags = re.findall(r"\s+(\w+)\s+", message)
            except Exception as e:
                self.core.logger("error", "syslog", "flow", f"Error extracting flags: {e}")
                return
            
            # Check if flags are present in the message
            if len(flags) > 0:
                for flag in flags:
                    message = message.replace(flag, "")
                    # Check for TCP Flags
                    if flag in tcp_flags:
                        tcp.append(flag)
                    else:
                        if flag == "DF":
                            flag = "dont_fragment"
                        self.record[flag] = "true"
            
            # Check if tcp flags are present
            if len(tcp) > 0:
                self.record["tcp_flags"] = tcp

            # Extract key=value pairs from the message
            pairs = re.findall(r"(\w+)=([^\s]+)", message)
            for key, value in pairs:
                # Map the keys to enriched keys
                try:
                    key = self.map.flow(key)
                    if key:
                        # Check if the key is in the label fields
                        if key in label_fields:
                            # Assign the value to labels with the mapped key
                            self.labels[key] = value
                        else:
                            # Assign the value to record with the mapped key
                            self.record[key] = value
                        
                        if key == "mac_address":
                            # Check the length of the MAC Address
                            if len(value) == 41:
                                mac_address_array = value.split(':')
                                self.record["source_mac"] = ':'.join(mac_address_array[0:6])
                                self.record["destination_mac"] = ':'.join(mac_address_array[6:12])
                                del self.record["mac_address"]
                        
                        elif key == "source_ip":
                            geo = self.geo.lookup(value)
                            if geo:
                                if geo.traits:
                                    self.record["source_traits"] = geo.traits
                                if geo.postal:
                                    self.record["source_postal"] = geo.postal
                                if geo.city:
                                    self.record["source_city"] = geo.city
                                if geo.subdivision:
                                    self.record["source_subdivision"] = geo.subdivision
                                if geo.latitude:
                                    self.record["source_latitude"] = geo.latitude
                                if geo.longitude:
                                    self.record["source_longitude"] = geo.longitude
                                if geo.country:
                                    self.labels["source_country"] = geo.country
                                if geo.continent:
                                    self.labels["source_continent"] = geo.continent
                            self.record["source_dns"] = self.map.ip(value)

                        elif key == "destination_ip":
                            geo = self.geo.lookup(value)
                            if geo:
                                if geo.traits:
                                    self.record["destination_traits"] = geo.traits
                                if geo.postal:
                                    self.record["destination_postal"] = geo.postal
                                if geo.city:
                                    self.record["destination_city"] = geo.city
                                if geo.subdivision:
                                    self.record["destination_subdivision"] = geo.subdivision
                                if geo.latitude:
                                    self.record["destination_latitude"] = geo.latitude
                                if geo.longitude:
                                    self.record["destination_longitude"] = geo.longitude
                                if geo.country:
                                    self.labels["destination_country"] = geo.country
                                if geo.continent:
                                    self.labels["destination_continent"] = geo.continent
                            self.record["destination_dns"] = self.map.ip(value)
                        
                        elif key == "source_interface" or key == "destination_interface":
                            if "br" in value:
                                vlan = self.core.extract(value, r"^br(\d+)", 1)
                                if vlan:
                                    self.labels[key] = f"VLAN {vlan.value}"
                        
                        elif key == "protocol":
                            self.labels["protocol"] = self.map.protocol(value)
                                
                    else:
                        self.core.logger("error", "syslog", "flow", f"Key not found in mapping: {key}")
                        return
                except Exception as e:
                    self.core.logger("error", "syslog", "flow", f"Error mapping flow keys: {e}")
                    return
            # Enrich Logs
            return self.Log(self.record, self.labels)

        def portforward(message: str) -> Syslog.Log:
            """
            Parses portforward-specific flow log fields from a Syslog message.

            Extracts portforward stage, type, ID, and rule name, then delegates
            further parsing to the common flow log parser.

            Args:
                message (str): The Syslog message to parse.

            Returns:
                Syslog.Log: Parsed log object with record and label data, or None if parsing fails.
            """
            self.labels["type"] = "portforward"
            # Parse PortForward Details - [PREROUTING-DNAT-4]
            forward_details = self.core.extract(message, r"^\[(\w+)-(\w+)-(\d+)\]", 0)
            if forward_details:                
                # Assign the parts to the labels
                self.labels["portforward_stage"] = self.core.extract(forward_details.value, r"\[(\w+)-(\w+)-(\d+)\]", 1).value
                self.labels["portforward_type"] = self.core.extract(forward_details.value, r"\[(\w+)-(\w+)-(\d+)\]", 2).value
                self.labels["portforward_id"] = self.core.extract(forward_details.value, r"\[(\w+)-(\w+)-(\d+)\]", 3).value

                # Extract the rule name from the message
                rule_name = self.core.extract(forward_details.cleaned, r"DESCR=\"(?:PortForward\s+\w+\s+\[(.+?)\]?)\"", 1)
                if rule_name:
                    # Map the rule name to a label
                    self.labels["portforward_rule"] = self.map.portforward(rule_name.value)
                    log = common(rule_name.cleaned)
                    return log
                else:
                    self.core.logger("error", "syslog", "flow", f"Rule name not found in message: {message}")
                    return
            else:
                self.core.logger("error", "syslog", "flow", f"Portforward details not found in message: {message}")
                return       

        def general(message: str) -> Syslog.Log:
            """
            Parses general (non-portforward) flow log fields from a Syslog message.

            Extracts source and destination zones, determines the action (permit, deny, or unknown)
            based on the description, and delegates further parsing to the common flow log parser.

            Args:
                message (str): The Syslog message to parse.

            Returns:
                Syslog.Log: Parsed log object with record and label data, or None if parsing fails.
            """
            self.labels["type"] = "flow"
            zone_info = self.core.extract(message, r"^\[(\w+)\S+\]", 1)
            if zone_info:
                zones = zone_info.value.split("_")
                if len(zones) == 2:
                    self.labels["source_zone"] = zones[0]
                    self.labels["destination_zone"] = zones[1]
                    description = self.core.extract(zone_info.cleaned, r"DESCR=\"(.+)\"", 1)
                    if description:
                        if "allow" in description.value.lower():
                            self.labels["action"] = "permit"
                        elif "block" in description.value.lower():
                            self.labels["action"] = "deny"
                        else:
                            self.labels["action"] = "unknown"
                        log = common(description.cleaned)
                        return log
                else:
                    self.core.logger("error", "syslog", "flow", f"Zone info not found in message: {message}")
                    return
                
        # extract the description from the message
        description = self.core.extract(message, r"DESCR=\"(.+)\"", 1)
        if description:
            # Check if the description is a portforward
            if "portforward" in description.value.lower():
                log = portforward(message)
                return log
            else:
                log = general(message)
                return log

    def parse(self, message: str, cached_ip: str) -> tuple:
        """
        Parses a Syslog message and exports the parsed data.

        This method extracts priority, facility, severity, timestamp, and hostname from the message.
        It determines whether the message is a flow log or a generic log, parses accordingly,
        and exports the resulting record and labels using the Loki exporter.

        Args:
            message (str): The Syslog message to parse.

        Returns:
            bool: True if the message was successfully parsed and exported, False otherwise.
        """
        self.core.logger("debug", "syslog", "parse", f"Starting to parse syslog message: {message}")

        # Set default values for tracking improvements
        self.labels["source"] = "unkown"
        self.labels["type"] = "unknown"
        self.labels["facility"] = "unknown"
        self.labels["level"] = "unknown"
        self.labels["hostname"] = "unknown"

        # Extract the priority value from the message
        priority = self.core.extract(message, r"^\<(\d+)\>", 1)
        self.core.logger("debug", "syslog", "parse", f"Extracted priority: {priority.value if priority else 'None'}")
        
        if priority.value:
            # Calculate facility and severity
            mapped_priority = self.map.priority(priority.value)
            self.core.logger("debug", "syslog", "parse", f"Mapped priority: {mapped_priority}")
            
            if mapped_priority.facility is not None:
                self.labels["facility"] = self.map.facility(mapped_priority.facility)
                self.core.logger("debug", "syslog", "parse", f"Assigned facility: {self.labels['facility']}")
            else:
                self.core.logger("error", "syslog", "parse", f"Unable to calculate facility from Priority: {priority.value}")
                return cached_ip, False
            
            if mapped_priority.severity is not None:
                self.labels["level"] = self.map.severity("syslog", mapped_priority.severity)
                self.core.logger("debug", "syslog", "parse", f"Assigned severity level: {self.labels['level']}")
            else:
                self.core.logger("error", "syslog", "parse", f"Unable to calculate severity from Priority: {priority.value}")
                return cached_ip, False
        else:
            self.core.logger("error", "syslog", "parse", f"Unable to extract priority from message: {message}")
            return cached_ip, False
        
        # Extract the timestamp from the message
        timestamp = self.core.extract(priority.cleaned, r"^([A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2})", 1)
        self.core.logger("debug", "syslog", "parse", f"Extracted timestamp: {timestamp.value if timestamp else 'None'}")
        
        if timestamp.value:
            # Extract the hostname from the message
            hostname = self.core.extract(timestamp.cleaned, r"(^\S+)\s", 1)
            self.core.logger("debug", "syslog", "parse", f"Extracted hostname: {hostname.value if hostname else 'None'}")
            
            if hostname.value:
                self.labels["hostname"] = re.sub(r"\s", "-", hostname.value)
                self.core.logger("debug", "syslog", "parse", f"Assigned hostname label: {self.labels['hostname']}")
                
                # Check if there is a description in the message
                description = self.core.extract(hostname.cleaned, r"DESCR=\"(.+)\"", 1)
                self.core.logger("debug", "syslog", "parse", f"Extracted description: {description.value if description else 'None'}")
                
                if description:
                    # Parse as a flow log
                    log = self.flow(hostname.cleaned)
                    if log:
                        self.core.logger("debug", "syslog", "parse", f"Parsed flow log: {log.record}, {log.labels}")
                        cached_ip, result = self.loki.export(log.record, log.labels, timestamp.value, cached_ip)
                        self.core.logger("debug", "syslog", "parse", f"Export status: {'Success' if result else 'Failure'}")
                        return cached_ip, result
                    else:
                        self.core.logger("error", "syslog", "parse", f"No log returned for flow log: {message}")
                        return cached_ip, False
                else:
                    # Parse as a generic log
                    log = self.generic(hostname.cleaned)
                    if log:
                        self.core.logger("debug", "syslog", "parse", f"Parsed generic log: {log.record}, {log.labels}")
                        cached_ip, result = self.loki.export(log.record, log.labels, timestamp.value, cached_ip)
                        self.core.logger("debug", "syslog", "parse", f"Export status: {'Success' if result else 'Failure'}")
                        return cached_ip, result
                    else:
                        self.core.logger("error", "syslog", "parse", f"No log returned for generic log: {message}")
                        return cached_ip, False
            else:
                self.core.logger("error", "syslog", "parse", f"Hostname not found in message: {timestamp.cleaned}")
                return cached_ip, False
        else:
            self.core.logger("error", "syslog", "parse", f"Timestamp not found in message: {message}")
            return cached_ip, False