import logging
from datetime import datetime
import os

def configure_logging(logger: logging.Logger, filename_suffix: str) -> None:
    """Centralized logging configuration"""
    # Ensure the 'logs' directory exists
    log_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%d-%Y")
    log_filename = f"{timestamp}-{filename_suffix}.log"
    log_path = os.path.join(log_dir, log_filename)
    abs_log_path = os.path.abspath(log_path)

    # Check for existing handlers using the absolute log path
    if not any(
        isinstance(h, logging.FileHandler) and h.baseFilename == abs_log_path
        for h in logger.handlers
    ):
        file_handler = logging.FileHandler(abs_log_path)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.setLevel(logging.INFO)