# -*- coding: utf-8 -*-
from __future__ import absolute_import
import logging
import os
import sys


def setup_logger(config):
    """Configure root logger from config dict.

    Args:
        config: full lswiz config dict

    Returns:
        logging.Logger: configured logger
    """
    log_config = config.get('log', {})
    level = getattr(logging, log_config.get('level', 'INFO').upper(), logging.INFO)
    log_file = log_config.get('file', '')

    logger = logging.getLogger('lswiz')
    logger.setLevel(level)

    # console handler
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    fmt = logging.Formatter('[%(levelname)s] %(message)s')
    console.setFormatter(fmt)
    logger.addHandler(console)

    # file handler (optional, skip if directory doesn't exist)
    if log_file:
        log_dir = os.path.dirname(log_file)
        if os.path.isdir(log_dir):
            try:
                fh = logging.FileHandler(log_file)
                fh.setLevel(level)
                file_fmt = logging.Formatter(
                    '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
                )
                fh.setFormatter(file_fmt)
                logger.addHandler(fh)
            except (IOError, OSError):
                logger.debug('Could not open log file: %s', log_file)

    return logger
