import configparser
import json
from ldap3 import BASE, SUBTREE, LEVEL
import logging
from pathlib import Path
from typing import NoReturn, Dict, List
from typing import List, NoReturn

from logging_custom.logging_custom import configure_logging

config_logger = logging.getLogger(__name__)


class Config:
    SCOPE_MAP = {
        'base': BASE,        # Search only the base object
        'subtree': SUBTREE,  # Search entire subtree (default)
        'onelevel': LEVEL    # Search single level (immediate children)
    }
    
    def __init__(self, config_file: str):
        self.config_file = Path(config_file)
        configure_logging(config_logger, "config-module")
        self._validate_config_file()
        self.configFileParser = configparser.ConfigParser()
        self._read_config()

    def _validate_config_file(self) -> None:
        """Comprehensive config file validation"""
        if not self.config_file.exists():
            self._critical_error(f"Config file {self.config_file} not found")
            
        try:
            with self.config_file.open('r') as f:
                pass  # Just verify readability
        except IOError as e:
            self._critical_error(f"Config file access error: {str(e)}")

    def _critical_error(self, message: str) -> NoReturn:
        """Consistent fatal error handling"""
        config_logger.critical(message, exc_info=True)
        raise SystemExit(1)

    def _read_config(self) -> None:
        """Safe config reading with validation"""
        try:
            with self.config_file.open('r') as f:
                self.configFileParser.read_file(f)
                
            if not self.configFileParser.sections():
                self._critical_error("Config file contains no valid sections")
                
        except configparser.Error as e:
            self._critical_error(f"Config parsing error: {str(e)}")

    def get_query_sections(self) -> List[str]:
        """Get all query-related sections safely"""
        return [s for s in self.configFileParser.sections() if s.startswith('query_')]

    def getNonQuerySections(self) -> List[str]:
        """Get list of all non-query sections"""
        sections = [
            section for section in self.configFileParser.sections()
            if not section.startswith('query_')
        ]
        config_logger.info(f"Retrieved {len(sections)} non-query sections from config")
        return sections

    def getADDomains(self) -> List[str]:
        """Get list of valid AD domain sections, excluding queries and system sections"""
        domains = [
            section for section in self.configFileParser.sections()
            if not section.startswith('query_') and not section in ['agent', 'backend-api', 'proxy']
        ]
        config_logger.info(f"Retrieved {len(domains)} AD domains from config")
        return domains

    def parseToJson(self) -> Dict:
        """Convert all non-query sections to JSON format"""
        config_dict = {}
        for section in self.getNonQuerySections():
            config_dict[section] = dict(self.configFileParser[section].items())
            config_logger.debug(f"Processed section: {section}")
        return config_dict
    
    def write(self, config_data: dict) -> None:
        """Write configuration to file"""
        try:
            self.configFileParser.read_dict(config_data)
            with open(self.configFile, 'w') as configFileObject:
                self.configFileParser.write(configFileObject)
            config_logger.info(f"Successfully wrote config to {self.configFile}")
        except Exception as e:
            config_logger.error(f"Failed to write config: {str(e)}")
            raise

if __name__ == '__main__':
    config_test = Config(config_file='./config.ini')
    config_json = config_test.parseToJson()
    config_queries = config_test.get_query_sections()
    
    print("Domain Configurations:")
    print(json.dumps(config_json, indent=2))
    
    print("\nQuery Sections:")
    print(config_queries)
