import logging
from datetime import datetime
from typing import List

def configure_logging(logger: logging.Logger, filename_suffix: str) -> None:
    """Centralized logging configuration"""
    timestamp = datetime.now().strftime("%d-%Y")
    log_filename = f"{timestamp}-{filename_suffix}.log"

    # Check for existing handlers
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename.endswith(log_filename) 
            for h in logger.handlers):
        file_handler = logging.FileHandler(log_filename)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.setLevel(logging.INFO)