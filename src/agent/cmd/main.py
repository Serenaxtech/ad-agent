import json
import os
from typing import Optional

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


def main_loop():
    read_config()

if __name__ == '__main__':
    main_loop()

