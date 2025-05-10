import json
import os
import argparse
import asyncio
import logging
from typing import Optional, Dict, Tuple, List

# Agent Internal Packages
from config.config import Config
from ldap.ldap import LdapConnector
from authenticator import AgentAuthChecker
from forwarder import HTTPForwarder, ForwarderError
from ftp.ftp import FTPScanner
from kerberos import Kerberos
# from recon import Recon

from logging_custom.logging_custom import configure_logging
# from recon import recon

netprotect_logger = logging.getLogger(__name__)
configure_logging(netprotect_logger, "netprotect-module")
netprotect_logger.info("NetProtect initialized")

VALID_SCAN_TYPES = ['kerberos', 'recon', 'ldap', 'ftp']

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
        netprotect_logger.error("Config file does not exist")
        return {}, {}
    
    config_reader = Config(config_file=config_filename)
    config_json = config_reader.parseToJson()
    config_queries = config_reader.get_query_sections()

    netprotect_logger.info("Successfully read configuration file")

    # print("Domain Configurations:")
    # print(json.dumps(config_json, indent=2))

    # print("\nQuery Sections:")
    # print(config_queries)

    return config_reader, config_queries, config_json

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

async def run_scan(scan_type: str, ldap_conn) -> Dict:
    """Run a specific scan type and return the results
    
    Args:
        scan_type (str): Type of scan to perform
        ldap_conn: LDAP connection object
        
    Returns:
        Dict: Scan results in the format {"scan_name": scan_type, "scan_result": result}
    """
    netprotect_logger.info(f"Running scan: {scan_type}")
    scan_result = {}
    
    if scan_type == 'ftp':
        try:
            # Initialize and run FTP scanner
            ftp_scanner = FTPScanner(ldap_conn)
            scan_result = ftp_scanner.scan_network_for_ftp(as_json=False)
            # print(scan_result)
        except Exception as e:
            netprotect_logger.error(f"Error during FTP scan: {e}")
            scan_result = {"error": str(e)}
    
    elif scan_type == 'ldap':
        scan_result = ldap_conn.query(ldapfilter="(objectClass=*)", as_json=True)
        print(scan_result)

    elif scan_type == 'kerberos':
        kerberos_scanner = Kerberos(ldap_conn)
        scan_result = kerberos_scanner.run_all_scans(as_json=False)

    else:
        # Placeholder for other scan types
        await asyncio.sleep(1)
        scan_result = {"status": "not implemented"}
    
    return {
        "scan_module": scan_type,
        "scan_result": scan_result
    }


def forward_result(base_url: str, endpoint: str, proxy_config: Dict[str, str], agent_config: Dict[str, str], scan_name: str, scan_result: str) -> None:
    try:
        agent_id = agent_config["agent-id"]
        agent_token = agent_config["auth-token"]

        proxy_url = normalize_proxy_value(proxy_config.get("proxy-url", ""))
        proxy_auth = normalize_proxy_value(proxy_config.get("proxy-auth", ""))

        forwarder = HTTPForwarder(proxy_url=proxy_url, proxy_auth=proxy_auth)

        payload = json.dumps({
            "scan_name": scan_name,
            "scan_result": scan_result,
            "agent_id": agent_id
        })

        headers = {
            'Content-Type': 'application/json',
            'x-agent-id': agent_id,
            'x-agent-token': agent_token
        }

        response = forwarder.forward_request("POST", f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}", headers=headers, data=payload)

        # Fix the logging calls by using f-strings
        netprotect_logger.info(f"Response Status Code: {response.status_code}")
        netprotect_logger.info(f"Response Body: {response.text}")

    except (KeyError, ForwarderError) as e:
        netprotect_logger.error(f"Error forwarding scan result: {e}")

def perform_recon(config_json, ):
    try:
        # Initialize configuration
        config = Config(config_file='./config.ini')
        # print(config.get_query_sections())
        # print(config.getADDomains())
        
        # Get first domain configuration (for demo purposes)
        domain = config.getADDomains()[0]
        domain_config = config.parseToJson()[domain]

        # Initialize LDAP connection
        ldap_conn = LdapConnector(
            server_string=f"ldap://{domain_config.get('ldap-server', '192.168.8.103')}",
            domain=domain,
            username=domain_config['username'].split('\\')[-1],  # Extract username from DOMAIN\user
            password=domain_config['password'],
            method=domain_config['auth-method']
        )

        # print(ldap_conn.query("(objectClass=Computer)", as_json=True))
        # Initialize Recon module
        recon = Recon(config, ldap_conn)

        # Test dynamic query methods
        print("\n=== Testing Dynamic Methods ===")
        
        # Get list of generated methods

        query_methods = [m for m in dir(recon) 
                    if m.startswith('get_') and callable(getattr(recon, m))]
        
        
        if not query_methods:
            print("No query methods found!")
            exit(1)

        # Execute all found query methods
        for method_name in query_methods:
            print(f"\nExecuting {method_name}():")
            
            try:
                method = getattr(recon, method_name)
                
                # Execute with default parameters
                results = method()
                
                # Convert generator to list for demonstration
                results_list = json.loads(results)
                
                # Print first 3 results as sample
                print(f"First 3 results from {method_name}:")
                for idx, item in enumerate(results_list[:3]):
                    print(f"{idx+1}: {json.dumps(item, indent=2)}")
                    
                # Full results count
                print(f"Total results: {len(results_list)}")
                
                # Test JSON output
                json_results = method(as_json=True)
                print(f"\nJSON output sample (first 100 chars):")
                print(json_results[:100] + "...")
                
            except Exception as e:
                print(f"Error in {method_name}: {str(e)}")
                continue

        # Test error handling
        print("\n=== Testing Error Handling ===")
        try:
            print("Attempting invalid query...")
            invalid_results = recon.get_all_users(override_filter="(invalidFilter)")
            list(invalid_results)  # Force generator execution
        except Exception as e:
            print(f"Properly handled error: {str(e)}")

    except Exception as e:
        logging.error(f"Critical test failure: {str(e)}")
        exit(1)


def main_loop() -> None:
    scan_types = parse_arguments()
    config_reader, config_queries, config_json = read_config()

    if not config_json:
        exit(-1)

    # print(config_json)
    base_url = config_json['backend-api'].get('base-api')
    base_endpoint = config_json['backend-api'].get('base-endpoint')

    is_authenticated = authenticate_agent(base_url, "/", config_json.get("proxy", {}), config_json.get("agent", {}))

    if is_authenticated:
        netprotect_logger.info(f"Authenticated. Ready to perform scan(s): {', '.join(scan_types)}")
    else:
        netprotect_logger.error("Agent is unauthenticated")
        exit(-1)

    # Initialize LDAP connection
    domain = config_reader.getADDomains()[0]
    domain_config = config_reader.parseToJson()[domain]

    ldap_conn = LdapConnector(
        server_string=f"ldap://192.168.8.112",
        domain=domain,
        username=domain_config['username'].split('\\')[-1],
        password=domain_config['password'],
        method=domain_config['auth-method']
    )

    async def perform_scans(ldap_conn):
        scan_results = await asyncio.gather(*(run_scan(scan, ldap_conn) for scan in scan_types))
        
        #print(scan_results)

        # Combine all scan results into a single dictionary
        combined_results = {}
        for result in scan_results:
            scan_name = result["scan_module"]
            scan_result = result["scan_result"]
            combined_results[scan_name] = scan_result
        
        # Forward the combined results
        forward_result(
            base_url=base_url + base_endpoint,
            endpoint="/scan/",
            proxy_config=config_json.get("proxy", {}),
            agent_config=config_json.get("agent", {}),
            scan_name="combined_scan",
            scan_result=json.dumps(combined_results)
        )

    asyncio.run(perform_scans(ldap_conn))


if __name__ == '__main__':
    main_loop()