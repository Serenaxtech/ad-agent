import configparser
from datetime import datetime
import json
import sys
import logging
from pathlib import Path
from typing import NoReturn

config_logger = logging.getLogger(__name__)

class Config:
    def __init__(self, config_file: str):
        self.configFile = config_file
        self._setup_logger()
        self._verify_file()
        self.configFileParser = configparser.ConfigParser()
        self._read_config()
        config_logger.info(f"Successfully loaded config file: {self.configFile}")
        
    def _setup_logger(self) -> None:
        """Initialize logger configuration"""
        # Generate filename: dd-yyyy-logfilename.log
        timestamp = datetime.now().strftime("%d-%Y")
        log_filename = f"{timestamp}-recon-module.log"

        # Check if the logger already has a FileHandler for this filename
        for handler in config_logger.handlers:
            if (
                isinstance(handler, logging.FileHandler)
                and handler.baseFilename.endswith(log_filename)
            ):
                break
        else:
            # Create a new FileHandler if none exists for this filename
            file_handler = logging.FileHandler(log_filename)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            file_handler.setFormatter(formatter)
            config_logger.addHandler(file_handler)

        # Set the logger level (optional, adjust as needed)
        config_logger.setLevel(logging.INFO)

    def _verify_file(self) -> None:
        """Validate config file exists and is accessible"""
        path = Path(self.configFile)
        config_logger.debug(f"Verifying config file: {path.resolve()}")

        if not path.is_file():
            self._critical_error(f"Config file {path} does not exist")
        
        if not path.exists():
            self._critical_error(f"Config file {path} cannot be accessed")
            
        try:
            path.open('r').close()
            config_logger.debug(f"File access check passed for {path}")
        except IOError as e:
            self._critical_error(f"Config file access error: {str(e)}")

    def _critical_error(self, message: str) -> NoReturn:
        """Handle fatal errors consistently"""
        config_logger.critical(message)
        config_logger.info("Application terminating due to critical error")
        sys.exit(1)

    def _read_config(self) -> None:
        """Read and validate config file contents"""
        try:
            with open(self.configFile, 'r') as f:
                self.configFileParser.read_file(f)
                config_logger.debug(f"Read {len(self.configFileParser.sections())} sections from config")
        except configparser.Error as e:
            self._critical_error(f"Invalid config format: {str(e)}")
        except Exception as e:
            self._critical_error(f"Unexpected error reading config: {str(e)}")

        if not self.configFileParser.sections():
            self._critical_error("Config file is empty or has no valid sections")

    def getADDomains(self) -> list:
        """Get list of AD domains from config"""
        ad_domains = self.configFileParser.sections()
        config_logger.info(f"Retrieved {len(ad_domains)} AD domains from config")
        return ad_domains

    def parseToJson(self) -> dict:
        """Convert config to JSON format"""
        config_dict = {}
        ad_domains = self.getADDomains()
        for ad_dom in ad_domains:
            config_dict[ad_dom] = dict(self.configFileParser[ad_dom].items())
        config_logger.debug(f"Converted config to JSON with {len(config_dict)} domains")
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
    config_test = Config(config_file= '../config.ini')
    config_json = config_test.parseToJson()
    print(config_json)
