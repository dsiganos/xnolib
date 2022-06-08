import logging
from logging.handlers import RotatingFileHandler


VERBOSE = 5
DEFAULT_LOGGER_NAME = ""  # an empty string will use the root logger


def get_logger(logger_name: str = DEFAULT_LOGGER_NAME) -> logging.Logger:
    logger = logging.getLogger(logger_name)
    if not logger.hasHandlers():
        logger.addHandler(logging.NullHandler())

    return logger


def setup_logger(logger: logging.Logger, level: int = VERBOSE) -> None:
    logging.addLevelName(VERBOSE, "VERBOSE")

    logger.setLevel(level)
    formatter = logging.Formatter("%(levelname)s %(asctime)s: %(message)s")

    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    f = RotatingFileHandler(logger.name + ".log", mode="a", maxBytes=(50 * 5000), backupCount=1)
    f.setLevel(level)
    f.setFormatter(formatter)
    logger.addHandler(f)
