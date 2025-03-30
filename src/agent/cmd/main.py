import json
import os
import argparse
import asyncio
from typing import Optional, Dict, Tuple, List

# Agent Internal Packages
from config.config import Config
from authenticator import AgentAuthChecker
from forwarder import HTTPForwarder, ForwarderError

VALID_SCAN_TYPES = ['kerberos', 'recon', 'ldap']

def find_config_file() -> Optional[str]:
    """
    Search for a file named 'config.ini' in the current working directory and in
    '/etc/netprotect'. Checks if the directories exist and handles errors properly.

    Returns:
        Optional[str]: Full path to the 'config.ini' file if found, otherwise None.
    """
    filenames_to_check = [
        os.path.join(os.getcwd(), "config.ini"),
        os.path.join("/etc/netprotect", "config.ini")
    ]

    for file_path in filenames_to_check:
        dir_path = os.path.dirname(file_path)

        try:
            if not os.path.isdir(dir_path):
                continue

            if os.path.isfile(file_path):
                return file_path

        except (OSError, PermissionError) as e:
            print(f"Error accessing {file_path}: {e}")
            continue

    return None

def read_config() -> Tuple[Dict, Dict]:
    config_filename = find_config_file()

    if config_filename is None:
        # I should replace this with proper logging
        print("Config file does not exist")
        return {}, {}
    
    config_test = Config(config_file=config_filename)
    config_json = config_test.parseToJson()
    config_queries = config_test.get_query_sections()

    print("Domain Configurations:")
    print(json.dumps(config_json, indent=2))

    print("\nQuery Sections:")
    print(config_queries)

    return config_queries, config_json

def authenticate_agent(base_url: str, proxy_config: Dict[str, str], agent_config: Dict[str, str]) -> bool:
    """
    Authenticates an agent using provided base URL, proxy configuration, and agent credentials.

    Args:
        base_url (str): The base URL of the authentication server.
        proxy_config (Dict[str, str]): A dictionary containing proxy configuration with optional keys:
            - 'proxy-url': The URL of the proxy server (can be 'None' or empty).
            - 'proxy-auth': The proxy authentication credentials (can be 'None' or empty).
        agent_config (Dict[str, str]): A dictionary containing agent credentials:
            - 'agent-id': The unique identifier for the agent.
            - 'auth-token': The authentication token for the agent.

    Returns:
        bool: True if authentication is successful, False otherwise.

    Raises:
        KeyError: If required keys are missing in the configuration dictionaries.
        Exception: If authentication fails due to unexpected errors.
    """
    try:
        agent_id = agent_config["agent-id"]
        agent_token = agent_config["auth-token"]

        proxy_url = proxy_config.get("proxy-url", "")
        proxy_auth = proxy_config.get("proxy-auth", "")

        # Normalize proxy values
        proxy_url = None if proxy_url in ("None", "") else proxy_url
        proxy_auth = None if proxy_auth in ("None", "") else proxy_auth

        auth_checker = AgentAuthChecker(
            base_url=base_url,
            agent_id=agent_id,
            agent_token=agent_token,
            proxy_url=proxy_url,
            proxy_auth=proxy_auth
        )

        return auth_checker.verify_authentication()

    except KeyError as e:
        print(f"Missing configuration key: {e}")
        raise
    except Exception as e:
        print(f"Authentication failed: {e}")
        return False

def parse_arguments() -> List[str]:
    """
    Parses command line arguments to determine one or more scan types.

    Returns:
        List[str]: A list of selected scan types.

    Raises:
        SystemExit: If any invalid scan types are provided.
    """
    parser = argparse.ArgumentParser(description="NetProtect Agent CLI")
    parser.add_argument(
        "-s", "--scan",
        type=str,
        required=True,
        help=f"Comma-separated list of scan types to perform. Options: {', '.join(VALID_SCAN_TYPES)}"
    )
    args = parser.parse_args()

    scan_types = [scan.strip() for scan in args.scan.split(',') if scan.strip()]
    invalid_types = [scan for scan in scan_types if scan not in VALID_SCAN_TYPES]

    if invalid_types:
        parser.error(f"Invalid scan type(s): {', '.join(invalid_types)}. Valid options: {', '.join(VALID_SCAN_TYPES)}")

    return scan_types

async def run_scan(scan_type: str) -> None:
    """
    Simulate running a scan by printing its name asynchronously.

    Args:
        scan_type (str): The type of scan to simulate.
    """
    print(f"Running scan: {scan_type}")
    await asyncio.sleep(1)  # Simulate async operation

def main_loop() -> None:
    scan_types = parse_arguments()
    config_queries, config_json = read_config()
    if not config_json:
        exit(-1)

    is_authenticated = authenticate_agent("http://localhost:3000", config_json.get("proxy", {}), config_json.get("agent", {}))

    if is_authenticated:
        print(f"Authenticated. Ready to perform scan(s): {', '.join(scan_types)}")
    else:
        print("Unauthenticated")
        exit(-1)

    async def perform_scans():
        await asyncio.gather(*(run_scan(scan) for scan in scan_types))

    asyncio.run(perform_scans())

if __name__ == '__main__':
    main_loop()
