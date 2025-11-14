"""
Logging Configuration for Threat Intelligence Platform
Provides centralized logging setup for all modules
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from datetime import datetime


class TIPLogger:
    """Centralized logging configuration for TIP"""

    _initialized = False
    _loggers = {}

    @classmethod
    def setup_logging(cls,
                     log_level: str = "INFO",
                     log_file: str = None,
                     enable_console: bool = True,
                     enable_file: bool = True,
                     enable_rotating: bool = True,
                     max_bytes: int = 10485760,  # 10MB
                     backup_count: int = 5):
        """
        Setup centralized logging configuration

        Args:
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file
            enable_console: Enable console logging
            enable_file: Enable file logging
            enable_rotating: Use rotating file handler
            max_bytes: Maximum size of log file before rotation
            backup_count: Number of backup files to keep
        """
        if cls._initialized:
            return

        # Create log directory if it doesn't exist
        if log_file:
            log_dir = Path(log_file).parent
            log_dir.mkdir(parents=True, exist_ok=True)
        else:
            log_dir = Path("logs")
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / f"tip_{datetime.now().strftime('%Y%m%d')}.log"

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_level.upper()))

        # Remove existing handlers
        root_logger.handlers = []

        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )

        # Console handler
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, log_level.upper()))
            console_handler.setFormatter(console_formatter)
            root_logger.addHandler(console_handler)

        # File handler
        if enable_file:
            if enable_rotating:
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=max_bytes,
                    backupCount=backup_count
                )
            else:
                file_handler = logging.FileHandler(log_file)

            file_handler.setLevel(getattr(logging, log_level.upper()))
            file_handler.setFormatter(detailed_formatter)
            root_logger.addHandler(file_handler)

        cls._initialized = True

        # Log initialization
        root_logger.info("="*80)
        root_logger.info("Threat Intelligence Platform - Logging Initialized")
        root_logger.info(f"Log Level: {log_level}")
        root_logger.info(f"Log File: {log_file}")
        root_logger.info("="*80)

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Get a logger instance for a module

        Args:
            name: Logger name (typically __name__)

        Returns:
            Logger instance
        """
        if not cls._initialized:
            cls.setup_logging()

        if name not in cls._loggers:
            cls._loggers[name] = logging.getLogger(name)

        return cls._loggers[name]

    @classmethod
    def set_level(cls, logger_name: str, level: str):
        """
        Set logging level for a specific logger

        Args:
            logger_name: Name of the logger
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, level.upper()))

    @classmethod
    def add_file_handler(cls, logger_name: str, log_file: str, level: str = "INFO"):
        """
        Add an additional file handler to a logger

        Args:
            logger_name: Name of the logger
            log_file: Path to log file
            level: Log level for this handler
        """
        logger = logging.getLogger(logger_name)

        # Create directory if needed
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

        # Create handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)

        # Add handler
        logger.addHandler(file_handler)


# Convenience function
def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance

    Args:
        name: Logger name (defaults to calling module name)

    Returns:
        Logger instance
    """
    if name is None:
        # Get caller's module name
        import inspect
        frame = inspect.currentframe().f_back
        name = frame.f_globals.get('__name__', 'tip')

    return TIPLogger.get_logger(name)


# Initialize logging on import if not already done
def initialize_from_config():
    """Initialize logging from configuration file"""
    try:
        import yaml
        config_path = Path(__file__).parent / "config.yaml"

        if config_path.exists():
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            logging_config = config.get('logging', {})

            TIPLogger.setup_logging(
                log_level=logging_config.get('level', 'INFO'),
                log_file=logging_config.get('file'),
                enable_console=True,
                enable_file=True
            )
        else:
            # Default configuration
            TIPLogger.setup_logging()

    except Exception as e:
        # Fallback to basic configuration
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logging.warning(f"Could not load logging configuration: {e}")


# Auto-initialize
if not TIPLogger._initialized:
    # Check if running in production or development
    if os.getenv('TIP_ENV') == 'production':
        TIPLogger.setup_logging(log_level='INFO')
    else:
        TIPLogger.setup_logging(log_level='DEBUG')


if __name__ == "__main__":
    # Test logging configuration
    TIPLogger.setup_logging(log_level='DEBUG')

    logger = get_logger(__name__)

    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")

    # Test module-specific logger
    collector_logger = TIPLogger.get_logger('collectors.test')
    collector_logger.info("Collector-specific log message")

    print("\nLogging test complete! Check logs/ directory for output")
