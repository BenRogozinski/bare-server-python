import logging

class CustomFormatter(logging.Formatter):

    blue =     "\x1b[34;20m"
    green =    "\x1b[32;20m"
    yellow =   "\x1b[33;20m"
    red =      "\x1b[31;20m"
    bold_red = "\x1b[31;7m"
    reset =    "\x1b[0m"

    format = "[%(asctime)s.%(msecs)03d] [%(name)s/%(levelname)s]: %(message)s"

    FORMATS = {
        logging.DEBUG: blue + format + reset,
        logging.INFO: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(fmt=log_fmt, datefmt="%F %T")
        return formatter.format(record)

def get_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    return logger