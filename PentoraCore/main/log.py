#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
from functools import partial
import logging as legacy_logger
from typing import Any

from loguru import logger as logging

from PentoraCore.language.vulnerability import MEDIUM_LEVEL

legacy_logger.getLogger("charset_normalizer").setLevel(legacy_logger.ERROR)
logging.remove()

# Setup additional logging levels, from the less important to the more critical
# Each attempted mutated request will be logged as VERBOSE as it generates a lot of output
# Each attacked original request will be logged as INFO
# Others info like currently used attack module must be logged even in quiet mode so BLUE level must be used as least

# logging.debug is level 10, this is the value defined in Python's logging module and is reused by loguru
logging.level("VERBOSE", no=15)
# logging.info is 20
RED = 45
GREEN = 22
BLUE = 21
ORANGE = 35

# Just create a color for log level (RED is already used by loguru so create a specific red for us)
logging.level("BLUE", no=BLUE, color="<blue>")
logging.level("GREEN", no=GREEN, color="<green>")  
logging.level("YELLOW", no=23, color="<yellow>")
logging.level("ORANGE", no=ORANGE, color="<yellow>")
logging.level("CYAN", no=24, color="<cyan>")
# RED Is for evil requests
logging.level("RED", no=RED, color="<red>")
# logging.success is 25
# logging.warning is 30
# logging.error is 40
# logging.critical is 50

log_blue = partial(logging.log, "BLUE")
log_green = partial(logging.log, "GREEN")  
log_red = partial(logging.log, "RED")
log_orange = partial(logging.log, "ORANGE")
log_yellow = partial(logging.log, "YELLOW")
log_cyan = partial(logging.log, "CYAN")
log_verbose = partial(logging.log, "VERBOSE")

# Set default logging
logging.add(sys.stdout, colorize=False, format="{message}", level="INFO")


def log_severity(level: int, message: str, *args: Any, **kwargs: Any) -> None:
    if level < MEDIUM_LEVEL:
        log_orange(message, args, kwargs)
    else:
        log_red(message, args, kwargs)
