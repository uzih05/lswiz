# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class PhpParser(BaseParser):
    """Parser for PHP."""

    names = ['php']
    cpe_vendor = 'php'
    cpe_product = 'php'

    def extract_version(self, binary_path):
        # php -v → "PHP 7.4.33 (cli) ..."
        output = self.run_command([binary_path, '-v'])
        return self.match_version(output, r'PHP\s+([\d.]+)')
