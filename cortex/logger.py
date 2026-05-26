import os
import logging
import structlog
from contextvars import ContextVar
import uuid

# Context variable to hold correlation IDs per request
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")

def add_correlation_id(logger, method_name, event_dict):
    """Add the correlation_id to the structured log dictionary."""
    cid = correlation_id.get()
    if cid:
        event_dict["correlation_id"] = cid
    return event_dict

def setup_logging(log_path: str = "/var/log/telos/cortex.log"):
    """Initialize structured logging (JSON or plain text)."""
    os.makedirs(os.path.dirname(log_path) or '.', exist_ok=True)
    
    log_format = os.environ.get("TELOS_LOG_FORMAT", "text").lower()
    
    # Configure stdlib logging
    logging.basicConfig(
        format="%(message)s",
        level=logging.INFO,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_path)
        ],
    )
    
    processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        add_correlation_id,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
        
    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    return structlog.get_logger("telos.cortex")

def get_logger(name: str):
    return structlog.get_logger(name)
