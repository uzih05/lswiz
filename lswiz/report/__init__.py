# -*- coding: utf-8 -*-
"""Report generation module."""
from __future__ import absolute_import

from lswiz.report.text_report import generate_text_report
from lswiz.report.json_report import generate_json_report
from lswiz.report.html_report import generate_html_report


def generate_report(results, fmt, config, logger):
    """Generate report in the specified format.

    Args:
        results: dict from doctor module
        fmt: 'text', 'json', or 'html'
        config: lswiz config dict
        logger: logger instance
    """
    generators = {
        'text': generate_text_report,
        'json': generate_json_report,
        'html': generate_html_report,
    }

    generator = generators.get(fmt, generate_text_report)
    generator(results, config, logger)
