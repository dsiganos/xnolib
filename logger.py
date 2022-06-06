import logging
from logging.handlers import RotatingFileHandler


VERBOSE = 5


class CustomLogger(logging.Logger):
    def verbose(self, msg, *args, **kwargs):
        if self.isEnabledFor(VERBOSE):
            self._log(VERBOSE, msg, args, **kwargs)


def setup_logging(logger_name: str, level: int = VERBOSE) -> CustomLogger:
    logging.addLevelName(VERBOSE, "VERBOSE")

    logging.setLoggerClass(CustomLogger)
    logger = logging.getLogger(logger_name)
    logging.setLoggerClass(logging.Logger)

    logger.setLevel(level)
    formatter = logging.Formatter("%(levelname)s %(asctime)s: %(message)s")

    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    f = RotatingFileHandler(logger_name + ".log", mode="a", maxBytes=(50 * 5000), backupCount=1)
    f.setLevel(level)
    f.setFormatter(formatter)
    logger.addHandler(f)

    assert isinstance(logger, CustomLogger)
    return logger
