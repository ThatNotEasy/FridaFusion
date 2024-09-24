from loguru import logger
import sys

def setup_logging():
    # Remove the default logger
    logger.remove()
    
    # Add a new logger with custom format, level, and color
    logger.add(
        sys.stderr,  # Log to standard error
        level="DEBUG",  # Set logging level
        format="<green>{time:YYYY-MM-DD at HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",  # Custom format with colors
        colorize=True  # Enable colored output
    )
    
    return logger  # Return the logger object