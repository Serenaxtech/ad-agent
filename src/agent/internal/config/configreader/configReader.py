import configparser
import json
import sys
import logging
from pathlib import Path
from typing import NoReturn

logger = logging.getLogger(__name__)

class Config:
    def __init__(self, config_file: str):
        self.configFile = config_file
        self._setup_logger()
        self._verify_file()
        self.configFileParser = configparser.ConfigParser()
        self._read_config()
        logger.info(f"Successfully loaded config file: {self.configFile}")

    def _setup_logger(self) -> None:
        """Initialize logger configuration"""
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)

    def _verify_file(self) -> None:
        """Validate config file exists and is accessible"""
        path = Path(self.configFile)
        logger.debug(f"Verifying config file: {path.resolve()}")

        if not path.is_file():
            self._critical_error(f"Config file {path} does not exist")
        
        if not path.exists():
            self._critical_error(f"Config file {path} cannot be accessed")
            
        try:
            path.open('r').close()
            logger.debug(f"File access check passed for {path}")
        except IOError as e:
            self._critical_error(f"Config file access error: {str(e)}")

    def _critical_error(self, message: str) -> NoReturn:
        """Handle fatal errors consistently"""
        logger.critical(message)
        logger.info("Application terminating due to critical error")
        sys.exit(1)

    def _read_config(self) -> None:
        """Read and validate config file contents"""
        try:
            with open(self.configFile, 'r') as f:
                self.configFileParser.read_file(f)
                logger.debug(f"Read {len(self.configFileParser.sections())} sections from config")
        except configparser.Error as e:
            self._critical_error(f"Invalid config format: {str(e)}")
        except Exception as e:
            self._critical_error(f"Unexpected error reading config: {str(e)}")

        if not self.configFileParser.sections():
            self._critical_error("Config file is empty or has no valid sections")

    def getADDomains(self) -> list:
        """Get list of AD domains from config"""
        ad_domains = self.configFileParser.sections()
        logger.info(f"Retrieved {len(ad_domains)} AD domains from config")
        return ad_domains

    def parseToJson(self) -> dict:
        """Convert config to JSON format"""
        config_dict = {}
        ad_domains = self.getADDomains()
        for ad_dom in ad_domains:
            config_dict[ad_dom] = dict(self.configFileParser[ad_dom].items())
        logger.debug(f"Converted config to JSON with {len(config_dict)} domains")
        return config_dict
    
    def write(self, config_data: dict) -> None:
        """Write configuration to file"""
        try:
            self.configFileParser.read_dict(config_data)
            with open(self.configFile, 'w') as configFileObject:
                self.configFileParser.write(configFileObject)
            logger.info(f"Successfully wrote config to {self.configFile}")
        except Exception as e:
            logger.error(f"Failed to write config: {str(e)}")
            raise

if __name__ == '__main__':
    config_test = Config(config_file= '../config.ini')
    config_json = config_test.parseToJson()
    print(type(config_json))
