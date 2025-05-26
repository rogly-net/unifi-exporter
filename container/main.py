# Import necessary modules
import signal
import socket
import os
import re
import time
import threading

# Import custom modules
from src.core import Core as core
from src.core import LokiExporter as loki
from src.core import GeoIP as geoip
from src.cef import Cef as cef
from src.syslog import Syslog as syslog

# Read the banner from the file
with open("src/banner.txt", "r") as banner_file:
    banner = banner_file.read()

# Config Banner
banner_config = rf"""
------------------------------------------------------------------------------
    Timezone: {os.getenv('TZ')}
    Log Level: {os.getenv('LOG_LEVEL')}
    Loki Endpoint: {os.getenv('LOKI_URL')}
    Syslog Port: {os.getenv('PORT')}
    Start Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
------------------------------------------------------------------------------
"""

# Set list of required environment variables
required_env_vars = [
    "LOG_LEVEL",
    "TZ",
    "LOKI_URL",
    "GEOIP_ACCOUNT_ID",
    "GEOIP_LICENSE_KEY"
]

# Initialize success and failure counts
success_count = 0
failure_count = 0
cached_ip = None

def counter():
    """
    Logs the number of successful and failed log exports to Loki every minute,
    then resets the counters for the next interval.
    """
    global success_count, failure_count
    while not core().stop_flag:
        core().logger("debug", "main", "counter", "Starting counter loop for the next interval.")
        time.sleep(60)  # Wait for 1 minute interval
        # Report counts for the last interval
        core().logger("informational", "main", "counter", f"Successfully exported {success_count} logs to Loki, Failed to export {failure_count} logs to Loki.")
        core().logger("debug", "main", "counter", "Resetting success and failure counters.")
        # Reset counters for next interval
        success_count = 0
        failure_count = 0

def evaluate(message):
    """
    Parses and evaluates an incoming log message to determine its format (syslog or CEF),
    processes it using the appropriate parser, and updates success or failure counters.

    Args:
        message (str): The incoming log message to be evaluated and parsed.
    """
    global success_count, failure_count, cached_ip

    if cached_ip is None:
        cached_ip = loki().cache_dns()

    core().logger("debug", "main", "evaluate", f"Received message for evaluation: {message}")

    # Strip null bytes and other non-printables to clean the input
    message = re.sub(r"[\x00-\x1F\x7F]", "", message).strip()
    core().logger("debug", "main", "evaluate", f"Cleaned message: {message}")

    # Identify syslog priority header e.g. "<34>"
    syslog_header = re.search(r"^<\d+>", message)

    # Identify Common Event Format header e.g. "CEF:0|"
    cef_header = re.search(r"CEF:\d+\|", message)

    if syslog_header:
        core().logger("debug", "main", "evaluate", "Message identified as syslog format")
        # Parse as syslog, increment corresponding counter
        cached_ip, result = syslog().parse(message, cached_ip)
        if result is True:
            success_count += 1
            core().logger("debug", "main", "evaluate", "Syslog message parsed successfully.")
        
        elif result is False:
            failure_count += 1
            core().logger("debug", "main", "evaluate", "Syslog message parsing failed.")

    elif cef_header:
        core().logger("debug", "main", "evaluate", "Message identified as CEF format.")
        # Parse as CEF, increment corresponding counter
        cached_ip, result = cef().parse(message, cached_ip)
        if result is True:
            success_count += 1
            core().logger("debug", "main", "evaluate", "CEF message parsed successfully.")
        elif result is False:
            failure_count += 1
            core().logger("debug", "main", "evaluate", "CEF message parsing failed.")

    else:
        # Skip empty messages silently
        if not message:
            core().logger("debug", "main", "evaluate", "Empty message received, skipping.")
            return
        
        # Log unknown formats for investigation
        core().logger("error", "main", "evaluate", f"Unknown message type: {message}")

def database_update():
    """
    Periodically checks and updates the GeoIP database every 12 hours.
    """
    geo = geoip()
    core().logger("debug", "main", "database_update", "Starting GeoIP database update thread.")
    while not core().stop_flag:
        core().logger("debug", "main", "database_update", "Sleeping for 12 hours before the next update check.")
        time.sleep(3600*12)  # Sleep for 12 hours
        core().logger("informational", "main", "database_update", "Checking if GeoIP database is up to date...")
        geo.update()

def main():
    """
    Main function to initialize the syslog server, set up signal handling,
    and start the GeoIP database update thread.
    """
    # Register the SIGTERM handler
    core().logger("debug", "main", "main", "Registering SIGTERM handler.")
    signal.signal(signal.SIGTERM, core().sigterm)
    
    # Print the Banner
    core().logger("debug", "main", "main", "Printing application banner.")
    print(banner, banner_config)

    # Check for required environment variables
    core().logger("informational", "main", "main", "Checking environment variables...")
    if core().environment(required_env_vars) == False:
        core().logger("critical", "main", "main", "Missing required environment variables.")
        exit(1)
    else:
        core().logger("informational", "main", "main", "All required environment variables are set.")

    # Start a thread for periodic GeoIP database checks
    core().logger("debug", "main", "main", "Starting GeoIP database update thread.")
    geoip_thread = threading.Thread(target=database_update, daemon=True)
    geoip_thread.start()

    # Set up a UDP socket to listen for syslog messages
    host = "0.0.0.0"
    port = int(os.getenv("PORT", "5514"))  # Default port is 5514
    core().logger("debug", "main", "main", f"Setting up UDP socket on {host}:{port}.")

    # Log the start of the syslog listener
    core().logger("informational", "main", "main", f"Starting syslog server...")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        core().logger("informational", "main", "main", f"Listening on {host}:{port}")
        counter_thread = threading.Thread(target=counter, daemon=True)
        counter_thread.start()
        try:
            while not core().stop_flag:
                sock.settimeout(1)  # Set a timeout in seconds to periodically check the stop flag
                try:
                    data, addr = sock.recvfrom(1024)  # Buffer size of 1024 bytes
                    core().logger("debug", "main", "main", f"Received data from {addr}: {data}")
                    if data:
                        # with open("config/raw.log", "a") as raw_log:
                        #     raw_log.write(data.decode('utf-8').strip() + "\n")
                        evaluate(data.decode('utf-8').strip())  # Send the message to the parser
                except socket.timeout:
                    core().logger("debug", "main", "main", "Socket timeout occurred, checking stop flag.")
                    continue  # Timeout occurred, check the stop flag again
        except KeyboardInterrupt:
            core().logger("critical", "main", "main", "Application interrupted by user.")
        finally:
            core().logger("critical", "main", "main", "Shutting down syslog server...")

if __name__ == "__main__":
    main()