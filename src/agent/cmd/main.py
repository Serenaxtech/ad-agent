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

def normalize_proxy_value(value: Optional[str]) -> Optional[str]:
    """
    Converts empty strings or "None" to None for proxy configuration.
    
    Args:
        value (Optional[str]): The proxy value to normalize.

    Returns:
        Optional[str]: Normalized proxy value.
    """
    return None if value in ("None", "") else value

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
        try:
            if os.path.isdir(os.path.dirname(file_path)) and os.path.isfile(file_path):
                return file_path
        except (OSError, PermissionError) as e:
            print(f"Error accessing {file_path}: {e}")
            continue

    return None

def read_config() -> Tuple[Dict, Dict]:
    config_filename = find_config_file()

    if config_filename is None:
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

def authenticate_agent(base_url: str, endpoint: str, proxy_config: Dict[str, str], agent_config: Dict[str, str]) -> bool:
    try:
        agent_id = agent_config["agent-id"]
        agent_token = agent_config["auth-token"]

        proxy_url = normalize_proxy_value(proxy_config.get("proxy-url", ""))
        proxy_auth = normalize_proxy_value(proxy_config.get("proxy-auth", ""))

        auth_checker = AgentAuthChecker(
            base_url=f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}",
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
    print(f"Running scan: {scan_type}")
    await asyncio.sleep(1)

def forward_result(base_url: str, endpoint: str, proxy_config: Dict[str, str], agent_config: Dict[str, str], scan_name: str, scan_result: str) -> None:
    try:
        agent_id = agent_config["agent-id"]

        proxy_url = normalize_proxy_value(proxy_config.get("proxy-url", ""))
        proxy_auth = normalize_proxy_value(proxy_config.get("proxy-auth", ""))

        forwarder = HTTPForwarder(proxy_url=proxy_url, proxy_auth=proxy_auth)

        payload = json.dumps({
            "scan_name": scan_name,
            "scan_result": scan_result,
            "agent_id": agent_id
        })

        headers = {'Content-Type': 'application/json'}

        response = forwarder.forward_request("POST", f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}", headers=headers, data=payload)

        print("Response Status Code:", response.status_code)
        print("Response Body:", response.text)

    except (KeyError, ForwarderError) as e:
        print(f"Error forwarding scan result: {e}")

def main_loop() -> None:
    scan_types = parse_arguments()
    config_queries, config_json = read_config()
    if not config_json:
        exit(-1)

    is_authenticated = authenticate_agent("http://localhost:3000", "/", config_json.get("proxy", {}), config_json.get("agent", {}))

    if is_authenticated:
        print(f"Authenticated. Ready to perform scan(s): {', '.join(scan_types)}")
    else:
        print("Unauthenticated")
        exit(-1)

    async def perform_scans():
        await asyncio.gather(*(run_scan(scan) for scan in scan_types))

    asyncio.run(perform_scans())

    forward_result(
        base_url="http://localhost:3000/api/v1",
        endpoint="/scan/",
        proxy_config=config_json.get("proxy", {}),
        agent_config=config_json.get("agent", {}),
        scan_name=", ".join(scan_types),
        scan_result="{kerberos: kerberoastable}"
    )

if __name__ == '__main__':
    main_loop()
