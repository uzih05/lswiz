# -*- coding: utf-8 -*-
"""Generic fallback parser for unknown binaries.

Tries common version flags in order. Used only when no dedicated parser
matches the binary name.
"""
from __future__ import absolute_import
import re
from lswiz.scanner.parsers.base import BaseParser

# version-like pattern: 1.2.3, 2.0, 10.3.1.4 etc.
VERSION_PATTERN = re.compile(r'(\d+\.\d+(?:\.\d+)*)')

# flags to try, in order of reliability
VERSION_FLAGS = [
    ['--version'],
    ['-v'],
    ['-V'],
    ['version'],
]


class GenericParser(BaseParser):
    """Fallback parser that tries common version flags."""

    names = []  # not registered by name; used as fallback
    cpe_vendor = ''
    cpe_product = ''

    def extract_version(self, binary_path):
        for flags in VERSION_FLAGS:
            output = self.run_command([binary_path] + flags)
            if not output:
                continue
            # take first line only to reduce noise
            first_line = output.split('\n')[0]
            m = VERSION_PATTERN.search(first_line)
            if m:
                return m.group(1)
        return None
