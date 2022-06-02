import logging
from logging.handlers import RotatingFileHandler


def setup_logging(logger_name: str) -> logging.Logger:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s %(asctime)s: %(message)s")

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    f = RotatingFileHandler(logger_name + ".log", mode="a", maxBytes=(50 * 5000), backupCount=1)
    f.setLevel(logging.DEBUG)
    f.setFormatter(formatter)
    logger.addHandler(f)

    return logger
