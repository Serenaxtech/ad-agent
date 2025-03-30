import json
import os
from typing import Optional, Dict

# Agent Internal Packages
from config.config import Config
from authenticator import AgentAuthChecker
from forwarder import HTTPForwarder, ForwarderError



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

def read_config():
    config_filename = find_config_file()
    
    if config_filename == None:
        # I should replace this with proper logging
        print("Config file does not exist")
    
    else:
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


def main_loop():
    config_queries, config_json = read_config()
    is_authenticated =  authenticate_agent("http://localhost:3000", config_json["proxy"], config_json["agent"])

    if is_authenticated:
        # I should replace this with proper logging using the logging library
        print("Authenticated")
    else:
        # I should replace this with proper logging using the logging library
        print("Unauthenticated")
        exit(-1)
    
    while True:
        pass

if __name__ == '__main__':
    main_loop()

